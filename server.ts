import 'dotenv/config';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import { and, desc, eq, gte, sql } from 'drizzle-orm';
import { db } from './src/db/index.ts';
import {
  admins,
  auditLogs,
  customers,
  packages,
  payments,
  routers,
  sessions,
  supportFeedback,
  transactions,
  vouchers,
} from './src/db/schema.ts';
import {
  getActivePackages,
  getAdminAnalytics,
  getAdminCount,
  getAdminOverviewMetrics,
  getAllPackagesAdmin,
  getPublicNetworkStatus,
  logAdminAction,
  searchCustomers,
  syncFirebaseUser,
} from './src/db/repository.ts';
import { adminAuth } from './src/lib/firebase-admin.ts';
import {
  createRateLimiter,
  encryptCredential,
  generateVoucherCode,
  hashPassword,
  normalizeKenyanPhone,
  signToken,
  verifyPassword,
} from './src/lib/security.ts';
import {
  requireAdminAuth,
  requireCustomerAuth,
  type AuthenticatedRequest,
} from './src/middleware/auth.ts';
import {
  disconnectHotspotUser,
  generateRouterSetupScript,
  provisionHotspotUser,
  testRouterConnectivity,
} from './src/services/mikrotik.ts';
import { initiateStkPush, processVerifiedMpesaCallback } from './src/services/mpesa.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// Rate limiters for sensitive endpoints
const stkPushLimiter = createRateLimiter({ windowMs: 60_000, max: 10, keyPrefix: 'stk' });
const loginLimiter = createRateLimiter({ windowMs: 60_000, max: 15, keyPrefix: 'login' });
const feedbackLimiter = createRateLimiter({ windowMs: 60_000, max: 8, keyPrefix: 'feedback' });

function getClientIp(req: express.Request): string {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    '127.0.0.1'
  );
}

function getBaseUrl(req: express.Request): string {
  if (process.env.APP_URL && process.env.APP_URL !== 'MY_APP_URL') {
    return process.env.APP_URL.replace(/\/$/, '');
  }
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3000';
  return `${proto}://${host}`;
}

// ============================================================================
// PUBLIC PORTAL & PACKAGE ROUTES
// ============================================================================

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'fastnet-wifi-portal' });
});

app.get('/api/network/status', async (_req, res) => {
  try {
    const status = await getPublicNetworkStatus();
    res.json(status);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Unable to fetch network status';
    res.status(500).json({ error: msg });
  }
});

app.get('/api/packages', async (_req, res) => {
  try {
    const list = await getActivePackages();
    res.json({ packages: list });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Unable to fetch packages';
    res.status(500).json({ error: msg });
  }
});

// ============================================================================
// SAFARICOM DARAJA M-PESA STK PUSH & CALLBACK ROUTES
// ============================================================================

app.post('/api/mpesa/stkpush', stkPushLimiter, async (req, res) => {
  try {
    const { phone, packageId, deviceInfo } = req.body as {
      phone?: string;
      packageId?: number;
      deviceInfo?: string;
    };

    if (!phone || !packageId || typeof packageId !== 'number') {
      return res.status(400).json({ error: 'Valid phone number and package selection required.' });
    }

    const result = await initiateStkPush({
      phoneInput: phone,
      packageId,
      deviceInfo: typeof deviceInfo === 'string' ? deviceInfo.slice(0, 120) : undefined,
      ipAddress: getClientIp(req),
      callbackBaseUrl: getBaseUrl(req),
    });

    res.json(result);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Failed to initiate M-Pesa STK Push.';
    res.status(400).json({ error: msg });
  }
});

app.get('/api/mpesa/status/:checkoutRequestId', async (req, res) => {
  try {
    const checkoutRequestId = req.params.checkoutRequestId;
    const rows = await db
      .select()
      .from(payments)
      .where(eq(payments.checkoutRequestId, checkoutRequestId))
      .limit(1);

    if (!rows.length) {
      return res.status(404).json({ error: 'Payment record not found.' });
    }

    const payment = rows[0];
    if (payment.status !== 'completed') {
      return res.json({
        status: payment.status,
        resultDesc: payment.resultDesc,
        amountKes: payment.amountKes,
        phone: payment.phone,
      });
    }

    const [customer] = await db
      .select()
      .from(customers)
      .where(eq(customers.id, payment.customerId))
      .limit(1);
    const [pkg] = await db
      .select()
      .from(packages)
      .where(eq(packages.id, payment.packageId))
      .limit(1);
    const voucherRows = payment.voucherId
      ? await db.select().from(vouchers).where(eq(vouchers.id, payment.voucherId)).limit(1)
      : [];
    const activeSessionRows = await db
      .select()
      .from(sessions)
      .where(and(eq(sessions.customerId, payment.customerId), eq(sessions.status, 'active')))
      .orderBy(desc(sessions.startedAt))
      .limit(1);

    const customerToken = customer
      ? signToken({
          sub: customer.phone,
          role: 'customer',
          username: customer.username,
          customerId: customer.id,
        })
      : null;

    res.json({
      status: payment.status,
      mpesaReceiptNumber: payment.mpesaReceiptNumber,
      amountKes: payment.amountKes,
      phone: payment.phone,
      voucherCode: voucherRows[0]?.code || null,
      username: customer?.username || null,
      package: pkg || null,
      session: activeSessionRows[0] || null,
      customerToken,
    });
  } catch (error: unknown) {
    console.error('M-Pesa status check error:', error);
    res.status(500).json({ error: 'Failed to check M-Pesa payment status.' });
  }
});

// Real Safaricom Daraja Callback Webhook
app.post('/api/mpesa/callback', async (req, res) => {
  try {
    const body = req.body as {
      Body?: {
        stkCallback?: {
          CheckoutRequestID?: string;
          ResultCode?: number;
          ResultDesc?: string;
          CallbackMetadata?: {
            Item?: Array<{ Name: string; Value?: string | number }>;
          };
        };
      };
    };

    const callback = body?.Body?.stkCallback;
    if (!callback?.CheckoutRequestID || typeof callback.ResultCode !== 'number') {
      return res.status(400).json({ error: 'Invalid Daraja callback payload.' });
    }

    const items = callback.CallbackMetadata?.Item || [];
    const receiptItem = items.find((i) => i.Name === 'MpesaReceiptNumber');
    const amountItem = items.find((i) => i.Name === 'Amount');

    await processVerifiedMpesaCallback({
      checkoutRequestId: callback.CheckoutRequestID,
      resultCode: callback.ResultCode,
      resultDesc: callback.ResultDesc || 'Processed',
      mpesaReceiptNumber: receiptItem?.Value ? String(receiptItem.Value) : undefined,
      amountPaid: amountItem?.Value ? Number(amountItem.Value) : undefined,
    });

    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  } catch (error: unknown) {
    console.error('Daraja callback processing error:', error);
    res.status(500).json({ ResultCode: 1, ResultDesc: 'Callback error' });
  }
});

// Sandbox STK PIN Simulation Confirmation (strictly disabled when real Daraja credentials are configured)
app.post('/api/mpesa/sandbox-confirm', stkPushLimiter, async (req, res) => {
  try {
    if (process.env.MPESA_CONSUMER_KEY && process.env.MPESA_CONSUMER_SECRET) {
      return res.status(403).json({
        error: 'Sandbox confirmation disabled while live Safaricom Daraja credentials are active.',
      });
    }

    const { checkoutRequestId, approve } = req.body as {
      checkoutRequestId?: string;
      approve?: boolean;
    };

    if (!checkoutRequestId) {
      return res.status(400).json({ error: 'Missing checkoutRequestId.' });
    }

    const result = await processVerifiedMpesaCallback({
      checkoutRequestId,
      resultCode: approve === false ? 1032 : 0,
      resultDesc:
        approve === false
          ? 'Request cancelled by user.'
          : 'The service request is processed successfully.',
    });

    if (!result.found) {
      return res.status(404).json({ error: 'Checkout request not found.' });
    }

    res.json({ ok: true, status: result.payment.status });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Payment confirmation failed.';
    res.status(400).json({ error: msg });
  }
});

// ============================================================================
// CAPTIVE PORTAL LOGIN, BALANCE CHECK & CUSTOMER DASHBOARD ROUTES
// ============================================================================

app.post('/api/portal/login', loginLimiter, async (req, res) => {
  try {
    const { mode, voucherCode, phone, username, password, deviceInfo } = req.body as {
      mode: 'voucher' | 'phone' | 'credentials';
      voucherCode?: string;
      phone?: string;
      username?: string;
      password?: string;
      deviceInfo?: string;
    };

    const now = new Date();
    const clientIp = getClientIp(req);
    const deviceLabel =
      typeof deviceInfo === 'string' && deviceInfo.trim()
        ? deviceInfo.trim().slice(0, 120)
        : 'Hotspot Client Device';

    if (mode === 'voucher') {
      const code = voucherCode?.trim().toUpperCase();
      if (!code) {
        return res.status(400).json({ error: 'Please enter your Fastnet voucher code.' });
      }

      const [voucher] = await db
        .select()
        .from(vouchers)
        .where(eq(vouchers.code, code))
        .limit(1);

      if (!voucher) {
        return res.status(404).json({ error: 'Voucher code not found. Check spelling and try again.' });
      }
      if (voucher.status === 'revoked' || voucher.status === 'expired' || voucher.status === 'used') {
        return res.status(400).json({ error: `This voucher is ${voucher.status} and cannot be used.` });
      }
      if (voucher.expiresAt && new Date(voucher.expiresAt) < now) {
        await db.update(vouchers).set({ status: 'expired' }).where(eq(vouchers.id, voucher.id));
        return res.status(400).json({ error: 'This voucher has expired.' });
      }

      const [pkg] = await db
        .select()
        .from(packages)
        .where(eq(packages.id, voucher.packageId))
        .limit(1);
      if (!pkg) {
        return res.status(404).json({ error: 'Package linked to this voucher no longer exists.' });
      }

      // If voucher is already active and tied to a session/customer, resume that session
      if (voucher.status === 'active' && voucher.redeemedByCustomerId) {
        const [customer] = await db
          .select()
          .from(customers)
          .where(eq(customers.id, voucher.redeemedByCustomerId))
          .limit(1);
        if (!customer || customer.status === 'blocked') {
          return res.status(403).json({ error: 'Account suspended. Contact Fastnet Support.' });
        }

        const activeSessions = await db
          .select()
          .from(sessions)
          .where(
            and(
              eq(sessions.voucherId, voucher.id),
              eq(sessions.status, 'active'),
              gte(sessions.expiresAt, now)
            )
          )
          .limit(1);

        let session = activeSessions[0];
        if (!session) {
          const expiresAt = voucher.expiresAt
            ? new Date(voucher.expiresAt)
            : new Date(now.getTime() + pkg.durationMinutes * 60_000);
          const [created] = await db
            .insert(sessions)
            .values({
              customerId: customer.id,
              packageId: pkg.id,
              voucherId: voucher.id,
              routerId: voucher.routerId,
              username: customer.username,
              macAddress: customer.macAddress || 'FA:5T:10:20:30:40',
              ipAddress: clientIp,
              deviceName: deviceLabel,
              speedMbpsDown: pkg.speedMbpsDown,
              speedMbpsUp: pkg.speedMbpsUp,
              dataLimitMb: pkg.dataLimitMb,
              dataUsedMb: 0,
              status: 'active',
              startedAt: now,
              expiresAt,
            })
            .returning();
          session = created;
        }

        const token = signToken({
          sub: customer.phone,
          role: 'customer',
          username: customer.username,
          customerId: customer.id,
        });

        return res.json({ customerToken: token, customer: { ...customer, passwordHash: undefined }, pkg, voucher, session });
      }

      // Unused voucher: redeem now!
      const normalizedPhone = phone ? normalizeKenyanPhone(phone) : null;
      const guestPhone = normalizedPhone || `254700${String(voucher.id).padStart(6, '0')}`;
      const guestUsername = `fn_v_${voucher.code.replace(/[^A-Z0-9]/g, '').toLowerCase()}`;

      const [customer] = await db
        .insert(customers)
        .values({
          phone: guestPhone,
          username: guestUsername,
          macAddress: `FA:5T:${crypto.randomBytes(4).toString('hex').toUpperCase().match(/.{2}/g)!.join(':')}`,
          ipAddress: clientIp,
          deviceInfo: deviceLabel,
          status: 'active',
          lastSeenAt: now,
        })
        .onConflictDoUpdate({
          target: customers.phone,
          set: { deviceInfo: deviceLabel, lastSeenAt: now },
        })
        .returning();

      const expiresAt = new Date(now.getTime() + pkg.durationMinutes * 60_000);
      const [onlineRouter] = await db
        .select()
        .from(routers)
        .where(eq(routers.status, 'online'))
        .limit(1);

      const [updatedVoucher] = await db
        .update(vouchers)
        .set({
          status: 'active',
          redeemedByCustomerId: customer.id,
          redeemedPhone: customer.phone,
          routerId: onlineRouter?.id || null,
          usedAt: now,
          expiresAt,
        })
        .where(eq(vouchers.id, voucher.id))
        .returning();

      const [session] = await db
        .insert(sessions)
        .values({
          customerId: customer.id,
          packageId: pkg.id,
          voucherId: voucher.id,
          routerId: onlineRouter?.id || null,
          username: customer.username,
          macAddress: customer.macAddress || 'FA:5T:00:11:22:33',
          ipAddress: clientIp,
          deviceName: deviceLabel,
          speedMbpsDown: pkg.speedMbpsDown,
          speedMbpsUp: pkg.speedMbpsUp,
          dataLimitMb: pkg.dataLimitMb,
          dataUsedMb: 0,
          status: 'active',
          startedAt: now,
          expiresAt,
        })
        .returning();

      await provisionHotspotUser(onlineRouter || null, {
        username: customer.username,
        password: updatedVoucher.code,
        speedMbpsDown: pkg.speedMbpsDown,
        speedMbpsUp: pkg.speedMbpsUp,
        durationMinutes: pkg.durationMinutes,
        dataLimitMb: pkg.dataLimitMb,
      });

      const token = signToken({
        sub: customer.phone,
        role: 'customer',
        username: customer.username,
        customerId: customer.id,
      });

      return res.json({
        customerToken: token,
        customer: { ...customer, passwordHash: undefined },
        pkg,
        voucher: updatedVoucher,
        session,
      });
    }

    if (mode === 'phone') {
      const normalized = phone ? normalizeKenyanPhone(phone) : null;
      if (!normalized) {
        return res.status(400).json({ error: 'Enter a valid Kenyan phone number (e.g. 0712345678).' });
      }

      const [customer] = await db
        .select()
        .from(customers)
        .where(eq(customers.phone, normalized))
        .limit(1);

      if (!customer) {
        return res.status(404).json({ error: 'No Fastnet account found for this phone number. Purchase a package first.' });
      }
      if (customer.status === 'blocked') {
        return res.status(403).json({ error: 'Your account is blocked. Contact Fastnet Support.' });
      }

      const activeSessions = await db
        .select()
        .from(sessions)
        .where(
          and(
            eq(sessions.customerId, customer.id),
            eq(sessions.status, 'active'),
            gte(sessions.expiresAt, now)
          )
        )
        .orderBy(desc(sessions.startedAt))
        .limit(1);

      if (!activeSessions.length) {
        return res.status(404).json({
          error: 'No active WiFi package found for this phone number. Please buy a package or enter a voucher.',
        });
      }

      const session = activeSessions[0];
      const [pkg] = await db.select().from(packages).where(eq(packages.id, session.packageId)).limit(1);
      const voucherRows = session.voucherId
        ? await db.select().from(vouchers).where(eq(vouchers.id, session.voucherId)).limit(1)
        : [];

      const token = signToken({
        sub: customer.phone,
        role: 'customer',
        username: customer.username,
        customerId: customer.id,
      });

      return res.json({
        customerToken: token,
        customer: { ...customer, passwordHash: undefined },
        pkg,
        voucher: voucherRows[0] || null,
        session,
      });
    }

    // mode === 'credentials' (Username & Password or Voucher as password)
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password/voucher passcode are required.' });
    }

    const trimmedUser = username.trim().toLowerCase();
    const [customer] = await db
      .select()
      .from(customers)
      .where(eq(customers.username, trimmedUser))
      .limit(1);

    if (!customer) {
      return res.status(401).json({ error: 'Invalid hotspot username or password.' });
    }
    if (customer.status === 'blocked') {
      return res.status(403).json({ error: 'Account blocked. Please contact Fastnet Support.' });
    }

    const activeSessions = await db
      .select()
      .from(sessions)
      .where(
        and(
          eq(sessions.customerId, customer.id),
          eq(sessions.status, 'active'),
          gte(sessions.expiresAt, now)
        )
      )
      .orderBy(desc(sessions.startedAt))
      .limit(1);

    const activeSession = activeSessions[0];
    const activeVoucherRows = activeSession?.voucherId
      ? await db.select().from(vouchers).where(eq(vouchers.id, activeSession.voucherId)).limit(1)
      : [];

    const validPasswordHash = customer.passwordHash
      ? verifyPassword(password, customer.passwordHash)
      : false;
    const matchesActiveVoucher =
      activeVoucherRows[0]?.code.toUpperCase() === password.trim().toUpperCase();

    if (!validPasswordHash && !matchesActiveVoucher) {
      return res.status(401).json({ error: 'Invalid hotspot password or voucher credential.' });
    }

    const [pkg] = activeSession
      ? await db.select().from(packages).where(eq(packages.id, activeSession.packageId)).limit(1)
      : [];

    const token = signToken({
      sub: customer.phone,
      role: 'customer',
      username: customer.username,
      customerId: customer.id,
    });

    res.json({
      customerToken: token,
      customer: { ...customer, passwordHash: undefined },
      pkg: pkg || null,
      voucher: activeVoucherRows[0] || null,
      session: activeSession || null,
    });
  } catch (error: unknown) {
    console.error('Portal login error:', error);
    res.status(500).json({ error: 'Unable to authenticate hotspot session.' });
  }
});

app.post('/api/portal/balance', loginLimiter, async (req, res) => {
  try {
    const { query } = req.body as { query?: string };
    const trimmed = query?.trim();
    if (!trimmed) {
      return res.status(400).json({ error: 'Enter your M-Pesa phone number or voucher code.' });
    }

    const now = new Date();
    const normalizedPhone = normalizeKenyanPhone(trimmed);

    if (normalizedPhone) {
      const [customer] = await db
        .select()
        .from(customers)
        .where(eq(customers.phone, normalizedPhone))
        .limit(1);
      if (!customer) {
        return res.status(404).json({ error: 'No Fastnet record found for this phone number.' });
      }

      const [activeSession] = await db
        .select()
        .from(sessions)
        .where(
          and(
            eq(sessions.customerId, customer.id),
            eq(sessions.status, 'active'),
            gte(sessions.expiresAt, now)
          )
        )
        .orderBy(desc(sessions.startedAt))
        .limit(1);

      const pkg = activeSession
        ? (await db.select().from(packages).where(eq(packages.id, activeSession.packageId)).limit(1))[0]
        : null;
      const voucher = activeSession?.voucherId
        ? (await db.select().from(vouchers).where(eq(vouchers.id, activeSession.voucherId)).limit(1))[0]
        : null;
      const history = await db
        .select()
        .from(payments)
        .where(eq(payments.customerId, customer.id))
        .orderBy(desc(payments.createdAt))
        .limit(10);

      const token = signToken({
        sub: customer.phone,
        role: 'customer',
        username: customer.username,
        customerId: customer.id,
      });

      return res.json({
        customerToken: token,
        customer: { ...customer, passwordHash: undefined },
        activeSession: activeSession || null,
        pkg: pkg || null,
        voucher: voucher || null,
        payments: history,
      });
    }

    // Lookup by voucher code
    const code = trimmed.toUpperCase();
    const [voucher] = await db.select().from(vouchers).where(eq(vouchers.code, code)).limit(1);
    if (!voucher) {
      return res.status(404).json({ error: 'No voucher or phone record matched your search.' });
    }

    const [pkg] = await db.select().from(packages).where(eq(packages.id, voucher.packageId)).limit(1);
    const [activeSession] = await db
      .select()
      .from(sessions)
      .where(and(eq(sessions.voucherId, voucher.id), eq(sessions.status, 'active')))
      .limit(1);

    res.json({
      voucher,
      pkg: pkg || null,
      activeSession: activeSession || null,
      payments: [],
    });
  } catch (error: unknown) {
    console.error('Balance check error:', error);
    res.status(500).json({ error: 'Failed to retrieve balance.' });
  }
});

app.get('/api/portal/session', requireCustomerAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const customerId = req.customerAuth!.customerId;
    const now = new Date();

    const [customer] = await db
      .select()
      .from(customers)
      .where(eq(customers.id, customerId))
      .limit(1);
    if (!customer) {
      return res.status(404).json({ error: 'Customer not found.' });
    }

    // Auto-expire sessions whose expiry timestamp has passed
    await db
      .update(sessions)
      .set({ status: 'expired', endedAt: now })
      .where(
        and(
          eq(sessions.customerId, customerId),
          eq(sessions.status, 'active'),
          sql`${sessions.expiresAt} <= ${now}`
        )
      );

    const [activeSession] = await db
      .select()
      .from(sessions)
      .where(
        and(
          eq(sessions.customerId, customerId),
          eq(sessions.status, 'active'),
          gte(sessions.expiresAt, now)
        )
      )
      .orderBy(desc(sessions.startedAt))
      .limit(1);

    const pkg = activeSession
      ? (await db.select().from(packages).where(eq(packages.id, activeSession.packageId)).limit(1))[0]
      : null;

    const voucher = activeSession?.voucherId
      ? (await db.select().from(vouchers).where(eq(vouchers.id, activeSession.voucherId)).limit(1))[0]
      : null;

    const paymentHistory = await db
      .select({
        id: payments.id,
        amountKes: payments.amountKes,
        mpesaReceiptNumber: payments.mpesaReceiptNumber,
        status: payments.status,
        createdAt: payments.createdAt,
        completedAt: payments.completedAt,
        packageName: packages.name,
        durationLabel: packages.durationLabel,
      })
      .from(payments)
      .leftJoin(packages, eq(payments.packageId, packages.id))
      .where(eq(payments.customerId, customerId))
      .orderBy(desc(payments.createdAt))
      .limit(20);

    res.json({
      customer: { ...customer, passwordHash: undefined },
      activeSession: activeSession || null,
      pkg: pkg || null,
      voucher: voucher || null,
      paymentHistory,
    });
  } catch (error: unknown) {
    console.error('Portal session fetch error:', error);
    res.status(500).json({ error: 'Failed to load customer session.' });
  }
});

app.post('/api/portal/logout', requireCustomerAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const customerId = req.customerAuth!.customerId;
    const now = new Date();

    const activeRows = await db
      .select()
      .from(sessions)
      .where(and(eq(sessions.customerId, customerId), eq(sessions.status, 'active')));

    for (const s of activeRows) {
      if (s.routerId) {
        const [router] = await db.select().from(routers).where(eq(routers.id, s.routerId)).limit(1);
        await disconnectHotspotUser(router || null, s.username);
      }
    }

    await db
      .update(sessions)
      .set({ status: 'disconnected', endedAt: now })
      .where(and(eq(sessions.customerId, customerId), eq(sessions.status, 'active')));

    res.json({ ok: true, message: 'Disconnected from Fastnet WiFi hotspot.' });
  } catch (error: unknown) {
    console.error('Portal logout error:', error);
    res.status(500).json({ error: 'Failed to disconnect session.' });
  }
});

app.post('/api/support/feedback', feedbackLimiter, async (req, res) => {
  try {
    const { name, phone, category, mpesaCode, message } = req.body as {
      name?: string;
      phone?: string;
      category?: string;
      mpesaCode?: string;
      message?: string;
    };

    if (!name?.trim() || !phone?.trim() || !message?.trim()) {
      return res.status(400).json({ error: 'Name, phone number, and message are required.' });
    }

    const [created] = await db
      .insert(supportFeedback)
      .values({
        name: name.trim().slice(0, 80),
        phone: phone.trim().slice(0, 20),
        category: ['payment', 'connection', 'package', 'general'].includes(category || '')
          ? category!
          : 'general',
        mpesaCode: mpesaCode?.trim().slice(0, 30) || null,
        message: message.trim().slice(0, 1000),
      })
      .returning();

    res.json({ ok: true, ticketId: created.id });
  } catch (error: unknown) {
    console.error('Support feedback error:', error);
    res.status(500).json({ error: 'Failed to submit support message.' });
  }
});

// ============================================================================
// ADMIN AUTHENTICATION & BOOTSTRAP ROUTES
// ============================================================================

app.get('/api/admin/auth/status', async (_req, res) => {
  try {
    const count = await getAdminCount();
    const hasEnvPass = Boolean(process.env.ADMIN_DEFAULT_PASSWORD?.trim());
    res.json({
      needsSetup: count === 0 && !hasEnvPass,
      hasAdmins: count > 0,
    });
  } catch (error: unknown) {
    console.error('Admin auth status error:', error);
    res.status(500).json({ error: 'Failed to check admin status.' });
  }
});

app.post('/api/admin/bootstrap', loginLimiter, async (req, res) => {
  try {
    if (process.env.ADMIN_DEFAULT_PASSWORD?.trim()) {
      return res.status(403).json({ error: 'Admin password is managed via environment secrets.' });
    }

    const { username, password, fullName, email } = req.body as {
      username?: string;
      password?: string;
      fullName?: string;
      email?: string;
    };

    if (!username?.trim() || !password || password.length < 8) {
      return res.status(400).json({
        error: 'Username and a strong password (at least 8 characters) are required.',
      });
    }

    const created = await db.transaction(async (tx) => {
      const existing = await tx.select({ count: sql<number>`count(*)::int` }).from(admins);
      if ((existing[0]?.count ?? 0) > 0) {
        return null;
      }

      const [adminRow] = await tx
        .insert(admins)
        .values({
          username: username.trim().toLowerCase(),
          fullName: fullName?.trim() || 'Fastnet Administrator',
          email: email?.trim() || null,
          passwordHash: hashPassword(password),
          role: 'superadmin',
          lastLoginAt: new Date(),
        })
        .returning();

      return adminRow;
    });

    if (!created) {
      return res.status(409).json({ error: 'Administrator account already claimed. Please log in.' });
    }

    await logAdminAction({
      adminId: created.id,
      adminUsername: created.username,
      action: 'ADMIN_BOOTSTRAP',
      targetType: 'admin',
      targetId: String(created.id),
      details: 'Initial administrator account claimed and secured.',
      ipAddress: getClientIp(req),
    });

    const token = signToken({
      sub: created.username,
      role: 'admin',
      username: created.username,
      adminId: created.id,
    });

    res.json({
      token,
      admin: { id: created.id, username: created.username, fullName: created.fullName, role: created.role },
    });
  } catch (error: unknown) {
    console.error('Admin bootstrap error:', error);
    res.status(500).json({ error: 'Failed to create initial administrator.' });
  }
});

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body as { username?: string; password?: string };
    if (!username?.trim() || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const envPass = process.env.ADMIN_DEFAULT_PASSWORD?.trim();

    let [adminRow] = await db
      .select()
      .from(admins)
      .where(eq(admins.username, cleanUsername))
      .limit(1);

    // If ADMIN_DEFAULT_PASSWORD is configured and matches for initial 'admin' login, provision/verify cleanly
    if (!adminRow && envPass && cleanUsername === 'admin' && password === envPass) {
      const [inserted] = await db
        .insert(admins)
        .values({
          username: 'admin',
          fullName: 'Fastnet Administrator',
          passwordHash: hashPassword(envPass),
          role: 'superadmin',
          lastLoginAt: new Date(),
        })
        .returning();
      adminRow = inserted;
    }

    const passwordValid =
      (adminRow && verifyPassword(password, adminRow.passwordHash)) ||
      (envPass && cleanUsername === 'admin' && password === envPass);

    if (!adminRow || !passwordValid) {
      return res.status(401).json({ error: 'Invalid administrator credentials.' });
    }

    if (!adminRow.isActive) {
      return res.status(403).json({ error: 'Administrator account is disabled.' });
    }

    await db.update(admins).set({ lastLoginAt: new Date() }).where(eq(admins.id, adminRow.id));

    await logAdminAction({
      adminId: adminRow.id,
      adminUsername: adminRow.username,
      action: 'ADMIN_LOGIN',
      targetType: 'admin',
      targetId: String(adminRow.id),
      details: 'Administrator signed in via password authentication.',
      ipAddress: getClientIp(req),
    });

    const token = signToken({
      sub: adminRow.username,
      role: 'admin',
      username: adminRow.username,
      adminId: adminRow.id,
    });

    res.json({
      token,
      admin: {
        id: adminRow.id,
        username: adminRow.username,
        fullName: adminRow.fullName,
        role: adminRow.role,
      },
    });
  } catch (error: unknown) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/admin/firebase-login', loginLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing Firebase ID token.' });
    }
    const idToken = authHeader.slice('Bearer '.length).trim();
    const decoded = await adminAuth.verifyIdToken(idToken);
    if (!decoded.email) {
      return res.status(400).json({ error: 'Google account email required.' });
    }

    await syncFirebaseUser(decoded.uid, decoded.email, decoded.name);

    let [adminRow] = await db
      .select()
      .from(admins)
      .where(eq(admins.email, decoded.email))
      .limit(1);

    // If zero admins exist yet, first Google Sign-In claims initial admin
    if (!adminRow) {
      const count = await getAdminCount();
      if (count === 0) {
        const [inserted] = await db
          .insert(admins)
          .values({
            username: decoded.email.split('@')[0].toLowerCase(),
            email: decoded.email,
            fullName: decoded.name || 'Fastnet Administrator',
            passwordHash: hashPassword(crypto.randomBytes(24).toString('hex')),
            firebaseUid: decoded.uid,
            role: 'superadmin',
            lastLoginAt: new Date(),
          })
          .returning();
        adminRow = inserted;
      }
    }

    if (!adminRow || !adminRow.isActive) {
      return res.status(403).json({
        error: 'This Google account is not authorized as a Fastnet administrator.',
      });
    }

    await logAdminAction({
      adminId: adminRow.id,
      adminUsername: adminRow.username,
      action: 'ADMIN_GOOGLE_LOGIN',
      targetType: 'admin',
      targetId: String(adminRow.id),
      details: `Signed in via Google (${decoded.email}).`,
      ipAddress: getClientIp(req),
    });

    const token = signToken({
      sub: adminRow.username,
      role: 'admin',
      username: adminRow.username,
      adminId: adminRow.id,
    });

    res.json({
      token,
      admin: {
        id: adminRow.id,
        username: adminRow.username,
        fullName: adminRow.fullName,
        role: adminRow.role,
      },
    });
  } catch (error: unknown) {
    console.error('Firebase admin login error:', error);
    res.status(401).json({ error: 'Google authentication verification failed.' });
  }
});

// ============================================================================
// PROTECTED ADMIN DASHBOARD ROUTES
// ============================================================================

app.get('/api/admin/overview', requireAdminAuth, async (_req, res) => {
  try {
    const metrics = await getAdminOverviewMetrics();
    res.json(metrics);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Failed to load overview.';
    res.status(500).json({ error: msg });
  }
});

app.get('/api/admin/customers', requireAdminAuth, async (req, res) => {
  try {
    const q = typeof req.query.q === 'string' ? req.query.q : undefined;
    const list = await searchCustomers(q);
    res.json({ customers: list });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Failed to load customers.';
    res.status(500).json({ error: msg });
  }
});

app.get('/api/admin/customers/:id/history', requireAdminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid customer ID.' });

    const [customerSessions, customerPayments] = await Promise.all([
      db
        .select({
          id: sessions.id,
          username: sessions.username,
          ipAddress: sessions.ipAddress,
          macAddress: sessions.macAddress,
          deviceName: sessions.deviceName,
          status: sessions.status,
          dataUsedMb: sessions.dataUsedMb,
          startedAt: sessions.startedAt,
          expiresAt: sessions.expiresAt,
          packageName: packages.name,
        })
        .from(sessions)
        .leftJoin(packages, eq(sessions.packageId, packages.id))
        .where(eq(sessions.customerId, id))
        .orderBy(desc(sessions.startedAt))
        .limit(20),
      db
        .select()
        .from(payments)
        .where(eq(payments.customerId, id))
        .orderBy(desc(payments.createdAt))
        .limit(20),
    ]);

    res.json({ sessions: customerSessions, payments: customerPayments });
  } catch (error: unknown) {
    console.error('Customer history error:', error);
    res.status(500).json({ error: 'Failed to load customer history.' });
  }
});

app.patch('/api/admin/customers/:id/action', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    const { action } = req.body as { action?: 'block' | 'activate' | 'disconnect' | 'reset' };
    if (!Number.isFinite(id) || !action) {
      return res.status(400).json({ error: 'Invalid customer action request.' });
    }

    const [customer] = await db.select().from(customers).where(eq(customers.id, id)).limit(1);
    if (!customer) return res.status(404).json({ error: 'Customer not found.' });

    if (action === 'block' || action === 'disconnect') {
      const activeSessions = await db
        .select()
        .from(sessions)
        .where(and(eq(sessions.customerId, id), eq(sessions.status, 'active')));

      for (const s of activeSessions) {
        const router = s.routerId
          ? (await db.select().from(routers).where(eq(routers.id, s.routerId)).limit(1))[0]
          : null;
        await disconnectHotspotUser(router || null, s.username);
      }

      await db
        .update(sessions)
        .set({ status: 'disconnected', endedAt: new Date() })
        .where(and(eq(sessions.customerId, id), eq(sessions.status, 'active')));
    }

    if (action === 'block') {
      await db.update(customers).set({ status: 'blocked' }).where(eq(customers.id, id));
    } else if (action === 'activate') {
      await db.update(customers).set({ status: 'active' }).where(eq(customers.id, id));
    } else if (action === 'reset') {
      const newPasscode = generateVoucherCode();
      await db
        .update(customers)
        .set({
          status: 'active',
          passwordHash: hashPassword(newPasscode),
          plainPasscodeHint: newPasscode,
        })
        .where(eq(customers.id, id));

      await logAdminAction({
        adminId: req.admin!.id,
        adminUsername: req.admin!.username,
        action: `CUSTOMER_RESET`,
        targetType: 'customer',
        targetId: String(id),
        details: `Reset portal access credentials for ${customer.phone}.`,
        ipAddress: getClientIp(req),
      });

      return res.json({ ok: true, resetPasscode: newPasscode });
    }

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: `CUSTOMER_${action.toUpperCase()}`,
      targetType: 'customer',
      targetId: String(id),
      details: `Performed ${action} on customer ${customer.phone}.`,
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true });
  } catch (error: unknown) {
    console.error('Customer action error:', error);
    res.status(500).json({ error: 'Failed to update customer status.' });
  }
});

// Admin Packages CRUD
app.get('/api/admin/packages', requireAdminAuth, async (_req, res) => {
  try {
    const list = await getAllPackagesAdmin();
    res.json({ packages: list });
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Failed to load packages.';
    res.status(500).json({ error: msg });
  }
});

app.post('/api/admin/packages', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const body = req.body as {
      name?: string;
      description?: string;
      category?: string;
      durationMinutes?: number;
      durationLabel?: string;
      priceKes?: number;
      speedMbpsDown?: number;
      speedMbpsUp?: number;
      dataLimitMb?: number | null;
      isPromo?: boolean;
      promoLabel?: string;
      isActive?: boolean;
    };

    if (!body.name?.trim() || !body.durationMinutes || !body.priceKes || body.priceKes < 1) {
      return res.status(400).json({ error: 'Package name, duration, and price are required.' });
    }

    const down = Math.max(1, Number(body.speedMbpsDown) || 15);
    const up = Math.max(1, Number(body.speedMbpsUp) || 10);
    const dataLimitMb =
      body.dataLimitMb && Number(body.dataLimitMb) > 0 ? Number(body.dataLimitMb) : null;
    const dataLabel = dataLimitMb
      ? dataLimitMb >= 1024
        ? `${(dataLimitMb / 1024).toFixed(dataLimitMb % 1024 === 0 ? 0 : 1)} GB`
        : `${dataLimitMb} MB`
      : 'Unlimited';

    const slugBase = body.name
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
    const slug = `${slugBase}-${Date.now().toString(36)}`;

    const [created] = await db
      .insert(packages)
      .values({
        name: body.name.trim(),
        slug,
        description: body.description?.trim() || 'High-speed Fastnet WiFi hotspot access.',
        category: body.category || 'custom',
        durationMinutes: Number(body.durationMinutes),
        durationLabel: body.durationLabel?.trim() || `${body.durationMinutes} Mins`,
        priceKes: Number(body.priceKes),
        speedMbpsDown: down,
        speedMbpsUp: up,
        speedLabel: `${down} Mbps`,
        dataLimitMb,
        dataLabel,
        isPromo: Boolean(body.isPromo),
        promoLabel: body.promoLabel?.trim() || null,
        isActive: body.isActive !== false,
        sortOrder: 50,
      })
      .returning();

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'PACKAGE_CREATE',
      targetType: 'package',
      targetId: String(created.id),
      details: `Created package "${created.name}" at KSh ${created.priceKes}.`,
      ipAddress: getClientIp(req),
    });

    res.json({ package: created });
  } catch (error: unknown) {
    console.error('Create package error:', error);
    res.status(500).json({ error: 'Failed to create package.' });
  }
});

app.patch('/api/admin/packages/:id', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid package ID.' });

    const body = req.body as Partial<{
      name: string;
      description: string;
      category: string;
      durationMinutes: number;
      durationLabel: string;
      priceKes: number;
      speedMbpsDown: number;
      speedMbpsUp: number;
      dataLimitMb: number | null;
      isPromo: boolean;
      promoLabel: string | null;
      isActive: boolean;
    }>;

    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (body.name !== undefined) updates.name = body.name.trim();
    if (body.description !== undefined) updates.description = body.description.trim();
    if (body.category !== undefined) updates.category = body.category;
    if (body.durationMinutes !== undefined) updates.durationMinutes = Number(body.durationMinutes);
    if (body.durationLabel !== undefined) updates.durationLabel = body.durationLabel.trim();
    if (body.priceKes !== undefined) updates.priceKes = Math.max(1, Number(body.priceKes));
    if (body.speedMbpsDown !== undefined) {
      const down = Math.max(1, Number(body.speedMbpsDown));
      updates.speedMbpsDown = down;
      updates.speedLabel = `${down} Mbps`;
    }
    if (body.speedMbpsUp !== undefined) updates.speedMbpsUp = Math.max(1, Number(body.speedMbpsUp));
    if (body.dataLimitMb !== undefined) {
      const lim = body.dataLimitMb && Number(body.dataLimitMb) > 0 ? Number(body.dataLimitMb) : null;
      updates.dataLimitMb = lim;
      updates.dataLabel = lim
        ? lim >= 1024
          ? `${(lim / 1024).toFixed(lim % 1024 === 0 ? 0 : 1)} GB`
          : `${lim} MB`
        : 'Unlimited';
    }
    if (body.isPromo !== undefined) updates.isPromo = Boolean(body.isPromo);
    if (body.promoLabel !== undefined) updates.promoLabel = body.promoLabel;
    if (body.isActive !== undefined) updates.isActive = Boolean(body.isActive);

    const [updated] = await db
      .update(packages)
      .set(updates)
      .where(eq(packages.id, id))
      .returning();

    if (!updated) return res.status(404).json({ error: 'Package not found.' });

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'PACKAGE_UPDATE',
      targetType: 'package',
      targetId: String(id),
      details: `Updated package "${updated.name}" (KSh ${updated.priceKes}, active: ${updated.isActive}).`,
      ipAddress: getClientIp(req),
    });

    res.json({ package: updated });
  } catch (error: unknown) {
    console.error('Update package error:', error);
    res.status(500).json({ error: 'Failed to update package.' });
  }
});

app.delete('/api/admin/packages/:id', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid package ID.' });

    // Check if referenced by payments or active sessions; if so, disable cleanly or delete if unused
    const refPayments = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(payments)
      .where(eq(payments.packageId, id));

    if ((refPayments[0]?.count ?? 0) > 0) {
      await db.update(packages).set({ isActive: false }).where(eq(packages.id, id));
      await logAdminAction({
        adminId: req.admin!.id,
        adminUsername: req.admin!.username,
        action: 'PACKAGE_ARCHIVE',
        targetType: 'package',
        targetId: String(id),
        details: `Archived package #${id} (preserved historical payments).`,
        ipAddress: getClientIp(req),
      });
      return res.json({ ok: true, archived: true });
    }

    await db.delete(packages).where(eq(packages.id, id));
    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'PACKAGE_DELETE',
      targetType: 'package',
      targetId: String(id),
      details: `Deleted package #${id}.`,
      ipAddress: getClientIp(req),
    });
    res.json({ ok: true });
  } catch (error: unknown) {
    console.error('Delete package error:', error);
    res.status(500).json({ error: 'Failed to delete package.' });
  }
});

// Admin Vouchers Management
app.get('/api/admin/vouchers', requireAdminAuth, async (_req, res) => {
  try {
    const rows = await db
      .select({
        id: vouchers.id,
        code: vouchers.code,
        packageId: vouchers.packageId,
        packageName: packages.name,
        durationLabel: packages.durationLabel,
        priceKes: vouchers.priceKes,
        status: vouchers.status,
        redeemedPhone: vouchers.redeemedPhone,
        batchId: vouchers.batchId,
        expiresAt: vouchers.expiresAt,
        usedAt: vouchers.usedAt,
        createdAt: vouchers.createdAt,
      })
      .from(vouchers)
      .leftJoin(packages, eq(vouchers.packageId, packages.id))
      .orderBy(desc(vouchers.createdAt))
      .limit(250);

    res.json({ vouchers: rows });
  } catch (error: unknown) {
    console.error('Fetch vouchers error:', error);
    res.status(500).json({ error: 'Failed to load vouchers.' });
  }
});

app.post('/api/admin/vouchers/generate', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { packageId, quantity, customPriceKes, expiresInDays } = req.body as {
      packageId?: number;
      quantity?: number;
      customPriceKes?: number;
      expiresInDays?: number;
    };

    if (!packageId) return res.status(400).json({ error: 'Package is required.' });
    const count = Math.min(100, Math.max(1, Number(quantity) || 1));

    const [pkg] = await db.select().from(packages).where(eq(packages.id, packageId)).limit(1);
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });

    const priceKes = customPriceKes && customPriceKes > 0 ? Number(customPriceKes) : pkg.priceKes;
    const daysValid = expiresInDays && expiresInDays > 0 ? Number(expiresInDays) : 30;
    const expiresAt = new Date(Date.now() + daysValid * 24 * 60 * 60 * 1000);
    const batchId = `BATCH-${Date.now().toString(36).toUpperCase()}`;

    const values = Array.from({ length: count }).map(() => ({
      code: generateVoucherCode(),
      packageId: pkg.id,
      priceKes,
      status: 'unused',
      batchId,
      expiresAt,
    }));

    const created = await db.insert(vouchers).values(values).returning();

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'VOUCHER_GENERATE',
      targetType: 'voucher_batch',
      targetId: batchId,
      details: `Generated ${count} voucher(s) for ${pkg.name} @ KSh ${priceKes}.`,
      ipAddress: getClientIp(req),
    });

    res.json({ vouchers: created, batchId });
  } catch (error: unknown) {
    console.error('Voucher generation error:', error);
    res.status(500).json({ error: 'Failed to generate vouchers.' });
  }
});

app.patch('/api/admin/vouchers/:id/revoke', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    const [updated] = await db
      .update(vouchers)
      .set({ status: 'revoked' })
      .where(eq(vouchers.id, id))
      .returning();
    if (!updated) return res.status(404).json({ error: 'Voucher not found.' });

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'VOUCHER_REVOKE',
      targetType: 'voucher',
      targetId: updated.code,
      details: `Revoked voucher ${updated.code}.`,
      ipAddress: getClientIp(req),
    });

    res.json({ voucher: updated });
  } catch (error: unknown) {
    console.error('Revoke voucher error:', error);
    res.status(500).json({ error: 'Failed to revoke voucher.' });
  }
});

// Admin Payments & Expenses
app.get('/api/admin/payments', requireAdminAuth, async (_req, res) => {
  try {
    const rows = await db
      .select({
        id: payments.id,
        phone: payments.phone,
        amountKes: payments.amountKes,
        mpesaReceiptNumber: payments.mpesaReceiptNumber,
        checkoutRequestId: payments.checkoutRequestId,
        status: payments.status,
        resultDesc: payments.resultDesc,
        paymentMode: payments.paymentMode,
        routerProvisioned: payments.routerProvisioned,
        createdAt: payments.createdAt,
        completedAt: payments.completedAt,
        packageName: packages.name,
      })
      .from(payments)
      .leftJoin(packages, eq(payments.packageId, packages.id))
      .orderBy(desc(payments.createdAt))
      .limit(200);

    res.json({ payments: rows });
  } catch (error: unknown) {
    console.error('Admin payments error:', error);
    res.status(500).json({ error: 'Failed to load payments.' });
  }
});

app.post('/api/admin/transactions/expense', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { description, amountKes } = req.body as { description?: string; amountKes?: number };
    if (!description?.trim() || !amountKes || amountKes <= 0) {
      return res.status(400).json({ error: 'Expense description and positive amount required.' });
    }
    const ref = `EXP-${Date.now().toString(36).toUpperCase()}`;
    const [created] = await db
      .insert(transactions)
      .values({
        type: 'expense',
        reference: ref,
        description: description.trim(),
        amountKes: Number(amountKes),
        status: 'posted',
      })
      .returning();

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'EXPENSE_LOG',
      targetType: 'transaction',
      targetId: ref,
      details: `Logged operating expense "${description.trim()}" (KSh ${amountKes}).`,
      ipAddress: getClientIp(req),
    });

    res.json({ transaction: created });
  } catch (error: unknown) {
    console.error('Expense log error:', error);
    res.status(500).json({ error: 'Failed to record expense.' });
  }
});

// Admin Analytics & Reports
app.get('/api/admin/analytics', requireAdminAuth, async (_req, res) => {
  try {
    const analytics = await getAdminAnalytics();
    res.json(analytics);
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Failed to load analytics.';
    res.status(500).json({ error: msg });
  }
});

// Admin MikroTik Routers & Active Sessions
app.get('/api/admin/routers', requireAdminAuth, async (_req, res) => {
  try {
    const list = await db.select().from(routers).orderBy(routers.id);
    const sanitized = list.map((r) => ({
      ...r,
      encryptedCredentials: undefined,
      hasCredentials: r.encryptedCredentials !== 'pending_config',
    }));
    res.json({ routers: sanitized });
  } catch (error: unknown) {
    console.error('Routers list error:', error);
    res.status(500).json({ error: 'Failed to load routers.' });
  }
});

app.post('/api/admin/routers', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const { name, location, ipAddress, apiPort, apiUsername, apiPassword, useTls, hotspotInterface } =
      req.body as {
        name?: string;
        location?: string;
        ipAddress?: string;
        apiPort?: number;
        apiUsername?: string;
        apiPassword?: string;
        useTls?: boolean;
        hotspotInterface?: string;
      };

    if (!name?.trim() || !location?.trim() || !ipAddress?.trim()) {
      return res.status(400).json({ error: 'Router name, location, and IP address are required.' });
    }

    const encrypted = apiPassword?.trim()
      ? encryptCredential(apiPassword.trim())
      : 'pending_config';

    const [created] = await db
      .insert(routers)
      .values({
        name: name.trim(),
        location: location.trim(),
        ipAddress: ipAddress.trim(),
        apiPort: Number(apiPort) || 8728,
        apiUsername: apiUsername?.trim() || 'admin',
        encryptedCredentials: encrypted,
        useTls: Boolean(useTls),
        hotspotInterface: hotspotInterface?.trim() || 'bridge-hotspot',
        status: 'online',
        uptimeSeconds: 3600,
      })
      .returning();

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'ROUTER_ADD',
      targetType: 'router',
      targetId: String(created.id),
      details: `Added MikroTik router "${created.name}" (${created.ipAddress}:${created.apiPort}).`,
      ipAddress: getClientIp(req),
    });

    res.json({
      router: {
        ...created,
        encryptedCredentials: undefined,
        hasCredentials: created.encryptedCredentials !== 'pending_config',
      },
    });
  } catch (error: unknown) {
    console.error('Add router error:', error);
    res.status(500).json({ error: 'Failed to add MikroTik router.' });
  }
});

app.patch('/api/admin/routers/:id', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    const body = req.body as Partial<{
      name: string;
      location: string;
      ipAddress: string;
      apiPort: number;
      apiUsername: string;
      apiPassword: string;
      useTls: boolean;
      hotspotInterface: string;
      status: string;
    }>;

    const updates: Record<string, unknown> = {};
    if (body.name !== undefined) updates.name = body.name.trim();
    if (body.location !== undefined) updates.location = body.location.trim();
    if (body.ipAddress !== undefined) updates.ipAddress = body.ipAddress.trim();
    if (body.apiPort !== undefined) updates.apiPort = Number(body.apiPort);
    if (body.apiUsername !== undefined) updates.apiUsername = body.apiUsername.trim();
    if (body.apiPassword?.trim()) updates.encryptedCredentials = encryptCredential(body.apiPassword.trim());
    if (body.useTls !== undefined) updates.useTls = Boolean(body.useTls);
    if (body.hotspotInterface !== undefined) updates.hotspotInterface = body.hotspotInterface.trim();
    if (body.status !== undefined) updates.status = body.status;

    const [updated] = await db.update(routers).set(updates).where(eq(routers.id, id)).returning();
    if (!updated) return res.status(404).json({ error: 'Router not found.' });

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'ROUTER_UPDATE',
      targetType: 'router',
      targetId: String(id),
      details: `Updated router "${updated.name}" (${updated.ipAddress}:${updated.apiPort}).`,
      ipAddress: getClientIp(req),
    });

    res.json({
      router: {
        ...updated,
        encryptedCredentials: undefined,
        hasCredentials: updated.encryptedCredentials !== 'pending_config',
      },
    });
  } catch (error: unknown) {
    console.error('Update router error:', error);
    res.status(500).json({ error: 'Failed to update router.' });
  }
});

app.post('/api/admin/routers/:id/test', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    const [router] = await db.select().from(routers).where(eq(routers.id, id)).limit(1);
    if (!router) return res.status(404).json({ error: 'Router not found.' });

    const testResult = await testRouterConnectivity(router);
    await db
      .update(routers)
      .set({
        status: testResult.reachable ? 'online' : 'offline',
        lastHeartbeatAt: new Date(),
      })
      .where(eq(routers.id, id));

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'ROUTER_TEST',
      targetType: 'router',
      targetId: String(id),
      details: testResult.message,
      ipAddress: getClientIp(req),
    });

    res.json(testResult);
  } catch (error: unknown) {
    console.error('Router test error:', error);
    res.status(500).json({ error: 'Router connectivity test failed.' });
  }
});

app.get('/api/admin/routers/:id/script', requireAdminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [router] = await db.select().from(routers).where(eq(routers.id, id)).limit(1);
    if (!router) return res.status(404).json({ error: 'Router not found.' });

    const portalHost = getBaseUrl(req).replace(/^https?:\/\//, '');
    const script = generateRouterSetupScript({
      name: router.name,
      hotspotInterface: router.hotspotInterface,
      apiPort: router.apiPort,
      apiUsername: router.apiUsername,
      portalHost,
    });
    res.json({ script });
  } catch (error: unknown) {
    console.error('Router script error:', error);
    res.status(500).json({ error: 'Failed to generate RouterOS script.' });
  }
});

app.get('/api/admin/sessions', requireAdminAuth, async (_req, res) => {
  try {
    const rows = await db
      .select({
        id: sessions.id,
        username: sessions.username,
        ipAddress: sessions.ipAddress,
        macAddress: sessions.macAddress,
        deviceName: sessions.deviceName,
        speedMbpsDown: sessions.speedMbpsDown,
        speedMbpsUp: sessions.speedMbpsUp,
        dataUsedMb: sessions.dataUsedMb,
        status: sessions.status,
        startedAt: sessions.startedAt,
        expiresAt: sessions.expiresAt,
        packageName: packages.name,
        customerPhone: customers.phone,
        routerName: routers.name,
      })
      .from(sessions)
      .leftJoin(packages, eq(sessions.packageId, packages.id))
      .leftJoin(customers, eq(sessions.customerId, customers.id))
      .leftJoin(routers, eq(sessions.routerId, routers.id))
      .orderBy(desc(sessions.startedAt))
      .limit(100);

    res.json({ sessions: rows });
  } catch (error: unknown) {
    console.error('Admin sessions error:', error);
    res.status(500).json({ error: 'Failed to load sessions.' });
  }
});

app.post('/api/admin/sessions/:id/disconnect', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    const [session] = await db.select().from(sessions).where(eq(sessions.id, id)).limit(1);
    if (!session) return res.status(404).json({ error: 'Session not found.' });

    const router = session.routerId
      ? (await db.select().from(routers).where(eq(routers.id, session.routerId)).limit(1))[0]
      : null;
    await disconnectHotspotUser(router || null, session.username);

    await db
      .update(sessions)
      .set({ status: 'disconnected', endedAt: new Date() })
      .where(eq(sessions.id, id));

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'SESSION_DISCONNECT',
      targetType: 'session',
      targetId: String(id),
      details: `Disconnected active session ${session.username} (${session.ipAddress}).`,
      ipAddress: getClientIp(req),
    });

    res.json({ ok: true });
  } catch (error: unknown) {
    console.error('Session disconnect error:', error);
    res.status(500).json({ error: 'Failed to disconnect session.' });
  }
});

app.get('/api/admin/audit-logs', requireAdminAuth, async (_req, res) => {
  try {
    const logs = await db
      .select()
      .from(auditLogs)
      .orderBy(desc(auditLogs.createdAt))
      .limit(100);
    res.json({ logs });
  } catch (error: unknown) {
    console.error('Audit logs error:', error);
    res.status(500).json({ error: 'Failed to load audit logs.' });
  }
});

app.get('/api/admin/feedback', requireAdminAuth, async (_req, res) => {
  try {
    const tickets = await db
      .select()
      .from(supportFeedback)
      .orderBy(desc(supportFeedback.createdAt))
      .limit(100);
    res.json({ tickets });
  } catch (error: unknown) {
    console.error('Feedback list error:', error);
    res.status(500).json({ error: 'Failed to load support tickets.' });
  }
});

app.patch('/api/admin/feedback/:id', requireAdminAuth, async (req: AuthenticatedRequest, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body as { status?: 'open' | 'resolved' };
    const [updated] = await db
      .update(supportFeedback)
      .set({ status: status === 'resolved' ? 'resolved' : 'open' })
      .where(eq(supportFeedback.id, id))
      .returning();

    if (!updated) return res.status(404).json({ error: 'Ticket not found.' });

    await logAdminAction({
      adminId: req.admin!.id,
      adminUsername: req.admin!.username,
      action: 'FEEDBACK_STATUS',
      targetType: 'support_feedback',
      targetId: String(id),
      details: `Marked support ticket #${id} as ${updated.status}.`,
      ipAddress: getClientIp(req),
    });

    res.json({ ticket: updated });
  } catch (error: unknown) {
    console.error('Feedback update error:', error);
    res.status(500).json({ error: 'Failed to update ticket status.' });
  }
});

// ============================================================================
// VITE DEV MIDDLEWARE / PRODUCTION STATIC HOSTING
// ============================================================================

async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`FASTNET WIFI Portal listening on http://0.0.0.0:${port}`);
  });
}

startServer();
