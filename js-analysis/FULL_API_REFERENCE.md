# Bokun Extranet - Full API Reference
## Extracted from 203 JS Files (13.1 MB total)

---

## Table of Contents
1. [Authentication & Headers](#1-authentication--headers)
2. [Hardcoded Secrets](#2-hardcoded-secrets)
3. [Activity Management API](#3-activity-management-api)
4. [Products API](#4-products-api)
5. [Availability Calendar API](#5-availability-calendar-api)
6. [Online Sales / Booking Channels API](#6-online-sales--booking-channels-api)
7. [Widget / Checkout API](#7-widget--checkout-api)
8. [Bookings API](#8-bookings-api)
9. [Admin API](#9-admin-api)
10. [User Management API](#10-user-management-api)
11. [Vendor Management API](#11-vendor-management-api)
12. [Chargebee / Payment API](#12-chargebee--payment-api)
13. [SaaS / Subscription API](#13-saas--subscription-api)
14. [Marketplace / Contracts API](#14-marketplace--contracts-api)
15. [Affiliates API](#15-affiliates-api)
16. [Connections / API Keys API](#16-connections--api-keys-api)
17. [Notification System API](#17-notification-system-api)
18. [Pusher WebSocket API](#18-pusher-websocket-api)
19. [AI Import / Katla API](#19-ai-import--katla-api)
20. [REST API v2.0](#20-rest-api-v20)
21. [Config / System API](#21-config--system-api)
22. [OTA Integrations](#22-ota-integrations)
23. [React Router Paths](#23-react-router-paths)
24. [Security Findings](#24-security-findings)

---

## 1. Authentication & Headers

### Custom Headers (sent on every request)
| Header | Type | Purpose |
|--------|------|---------|
| `X-Bokun-Fetch: true` | boolean | Marks authenticated fetch wrapper calls |
| `X-Bokun-Currency` | string | Vendor currency context |
| `X-Bokun-Language` | string | Vendor language context |
| `X-Bokun-Session` | string | Session identifier |
| `X-Bokun-Source` | string | Request source tracking |
| `X-Bokun-Host-Url` | string | Host URL context |
| `checkout-api-token` | string | Checkout authentication |
| `bokun-Use-Session: true` | boolean | Turnstile/CAPTCHA requests |

### Auth Methods
- **Cookie-based**: `credentials: "same-origin"` on all fetch calls
- **Basic Auth**: `Authorization: Basic` for API key/password combos (Axios)
- **Cloudflare Turnstile**: Site key `87034e40f67c0b3c7e5d77cd36317897`
- **CAPTCHA bypass**: IP-based `bypassCaptcha` mechanism

---

## 2. Hardcoded Secrets

| Secret | Value | File | Risk |
|--------|-------|------|------|
| **Google API Key** | `AIzaSyDFiCTOFiP5Yzdp0CMA8hyOmsMuyWmUvs0` | `jxUSq5-o.js` | HIGH |
| **Sentry DSN** | `https://87034e40f67c0b3c7e5d77cd36317897@o4509650126700544.ingest.us.sentry.io/4509650144460800` | multiple | MEDIUM |
| **Avo Inspector Code** | `md5vBrymXoYmafwurwLP` | `jxUSq5-o.js` | LOW |
| **Sentry Release** | `06806a458fe6d81d90e329d4fff15b2c88434562` | all chunks | LOW |

---

## 3. Activity Management API

### Activity CRUD
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/activities/editor/activity-options` | `?id={id}` |
| POST | `/activities/editor/create` | JSON activity object |
| PATCH | `/activities/editor/:id` | JSON activity update |
| POST | `/activities/editor/:id/update-milestone` | milestone data |
| POST | `/activities/editor/:aid/publish` | - |
| POST | `/activities/editor/:aid/unpublish` | - |
| GET | `/activities/editor/config/:id` | activity ID |
| GET | `/products/activities/:id/pre-delete` | activity ID |

### Start Times
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/activities/editor/starttimes/:aid/create` | start time data |
| PATCH | `/activities/editor/starttimes/:id/update` | start time update |
| DELETE | `/activities/editor/starttimes/:id/delete` | - |
| GET | `/activities/editor/starttimes/:aid/impacts-availability` | - |
| GET | `/activities/editor/starttimeavailabilities/:id/get` | availability ID |

### Rates
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/activities/editor/rates` | `?activityRateId={id}&title={title}` |
| POST | `/activities/editor/rate-clone` | `?activityRateId={id}&title={title}` |
| POST | `/activities/editor/rates/change-order` | `?ruleId={id}&prevId={id}` |
| POST | `/activities/editor/rates-extras` | `?rateId={id}` |
| DELETE | `/activities/editor/rates/:rateId` | - |

### Extras
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/activities/editor/extras/:aid` | extra data |
| PATCH | `/activities/editor/extras/:id` | extra update |
| DELETE | `/activities/editor/extras/:id` | - |

### Agenda Items
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/activities/editor/agendaitems/:aid/create` | agenda item |
| PATCH | `/activities/editor/agendaitems/:id/update` | agenda update |
| DELETE | `/activities/editor/agendaitems/:id/delete` | - |
| POST | `/activities/editor/agendaitems/:agendaItemId/move` | `?prevAgendaItemId={id}` |

### Photos
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/activities/editor/photos/:aid/photo/:id/make-key` | photo ID |
| GET | `/activities/editor/photos/:aid/photo/move` | - |
| POST | `/activities/editor/photos/:aid/s3/success-callback` | S3 callback data |
| POST | `/activities/editor/photos/update` | photo data |
| POST | `/activities/editor/photos/:aid/photo/delete` | - |

### Pickup / Place Groups
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/activities/editor/pickup-options` | - |
| POST | `/activities/editor/pickupplaces/create` | pickup place data |
| PATCH | `/activities/editor/pickupplaces/:id/update` | pickup update |
| DELETE | `/activities/editor/pickupplaces/:id/delete` | - |
| GET | `/activities/editor/placegroups/list-json` | - |
| GET | `/activities/editor/placegroups/:id/get` | place group ID |
| POST | `/activities/editor/placegroups/create` | place group data |
| PATCH | `/activities/editor/placegroups/:id/update` | place group update |
| DELETE | `/activities/editor/placegroups/:id/delete` | - |
| POST | `/activities/editor/combopickup/:aid` | pickup config |
| DELETE | `/activities/editor/opening-hours/:id/clear` | - |

### Combo Start Times
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/activities/editor/combostarttimes/:csid` | combo start times |
| GET | `/activities/editor/combostarttimes/listsuppliers` | - |
| GET | `/activities/editor/combostarttimes/listproducts/:sid/:caid` | supplier/category IDs |
| GET | `/activities/editor/combostarttimes/product/:aid` | activity ID |

### Start Points
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/activities/:aid/start-points` | start point data |
| PATCH | `/activities/:aid/start-points/:spid` | start point update |
| DELETE | `/activities/:aid/start-points/:spid` | - |

### Translations
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| DELETE | `/activities/translations/:id/:lang` | translation ID/lang |

---

## 4. Products API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/products/activities/json` | - |
| POST | `/products/activities/:aid/questions/save` | questions data |
| DELETE | `/products/activities/:aid/questions/:id/delete` | question ID |
| POST | `/products/activities/:aid/questions/move` | `?id={id}&prevId={id}` |
| POST | `/products/activities/:aid/enhanced-connectivity/enable/json` | - |
| GET | `/products/activities/:aid/enhanced-connectivity/json` | - |
| POST | `/products/activities/:aid/enhanced-connectivity/json` | connectivity data |
| GET | `/products/:category/:id/pricing/json/default` | category/ID |
| GET | `/products/activities/import/viator/list/:supplierId` | `?locale={locale}&page={page}&pagingTimestamp={ts}` |
| GET | `/products/activities/import/viator/product/:bokunId` | bokun activity ID |
| POST | `/products/activities/import/viator` | import config |
| GET | `/products/gift-cards` | - |
| GET | `/products/price-schedules` | - |
| GET | `/products/resource-management` | - |
| GET | `/product-extension/pricing-categories` | - |
| GET | `/product-extension/pricing-categories/:id/usage` | category ID |
| GET | `/product-extension/offers` | - |
| GET | `/product-extension/offers/:id` | offer ID |

---

## 5. Availability Calendar API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/availability-calendar/:aid` | activity ID |
| POST | `/closeouts/toggle` | `{date, activityIds, startTimeIds, closed}` |
| POST | `/availability-calendar/correct-rules/:aid` | activity ID |
| POST | `/availability-calendar/:aid/rules/create` | rule data |
| PATCH | `/availability-calendar/rules/:id` | rule update |
| POST | `/availability-calendar/:aid/rules/exception` | exception data |
| DELETE | `/availability-calendar/rules/:id` | rule ID |
| DELETE | `/availability-calendar/clear-rules/:activityId` | activity ID |
| POST | `/availability-calendar/rules/change-order` | `?ruleId={id}&prevId={id}` |

---

## 6. Online Sales / Booking Channels API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/online-sales-editor` | - |
| POST | `/online-sales-editor/create` | channel config |
| GET | `/online-sales-editor/:id/booking-channel-options` | channel ID |
| GET | `/online-sales-editor/:id/currency-options` | channel ID |
| PATCH | `/online-sales-editor/:id/update` | `?editorStep={step}&editorGroup={group}` |
| PATCH | `/online-sales-editor/:id/update-product-page` | product page config |
| PATCH | `/online-sales-editor/:id/update-booking-portal` | portal config |
| PATCH | `/online-sales-editor/:id/update-product-list` | product list config |
| PATCH | `/online-sales-editor/:id/update-shopping-cart` | cart config |
| PATCH | `/online-sales-editor/:id/update-calendar` | calendar config |
| PATCH | `/online-sales-editor/:id/update-website` | website config |
| PATCH | `/online-sales-editor/:id/update-checkout` | checkout config |
| POST | `/online-sales-editor/:id/photos/s3/success-callback` | S3 callback |
| DELETE | `/online-sales-editor/:id/photos/s3/delete-photo` | - |
| DELETE | `/online-sales-editor/:id/delete` | - |
| GET | `/booking-channels/suggest-channel-all` | - |

---

## 7. Widget / Checkout API

### Widget Client (Sf)
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/widgets/:uuid/checkout/extras` | extra selection data |
| DELETE | `/widgets/:uuid/checkout/extras/remove` | extra removal data |
| POST | `/widgets/:uuid/checkout/mainContactAnswers` | `{answers: [...]}` |
| POST | `/widgets/:uuid/checkout/activityBookingAnswers` | `{activityId, bookingId, answers, passengers, pickupAnswers, dropoffAnswers}` |
| GET | `/widgets/:uuid/checkout/cartBookingOptions` | - |
| GET | `/widgets/:uuid/loaded` | `?widgetUrl={url}&refererUrl={url}&isBookingButton={bool}` |

### Widget Wizard
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/widget-channels` | - |
| GET | `/widget-wizard/product-lists` | - |
| GET | `/widget-wizard/suggest-activity` | - |
| GET | `/widget-wizard/suggest-suppliers` | - |

### Dynamic Payment Endpoints (set server-side)
| Endpoint | Purpose |
|----------|---------|
| `{checkoutOptionsEndpoint}` | Checkout options |
| `{processCheckoutEndpoint}` | Process checkout |
| `{processRedirectBookingReceiptEndpoint}` | Redirect receipt |
| `{ppcpCreateOrderEndpoint}` | PayPal Commerce Platform order |
| `{utiEndpoint}` | UTI token |

### Widget Routes
- `/`, `/search`, `/contact`
- `/experience-calendar/:activityId`
- `/product-list/:productListId`
- `/experience/:activityId`
- `/images/:activityId/:imageId`
- `/checkout`, `/checkout/main-contact`
- `/checkout/activity-booking/:activityBookingId`
- `/checkout/product-booking-questions`
- `/checkout/refund-terms`, `/checkout/payment`
- `/booking-receipt/:bookingId/:bookingHash`
- `/gift-card/:giftCardId`, `/gift-card/:activityId/:giftCardOptionId`
- `/disabled`

---

## 8. Bookings API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `/bookings/activity-search-json` | search filters |
| GET | `/sales/:id/json` | booking ID |
| GET | `/booking/:id/payments/json` | booking ID |
| GET | `/booking-calendar/departure-details/:availabilityId` | availability ID |
| POST | `/booking-area/booking-answers` | booking answers |
| GET | `/booking-area/booking-questions` | - |
| GET | `/bookings/agent` | - |

### Viator Import
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/bookings/activity/importstatus/viator/:supplierId` | supplier ID |
| GET | `/bookings/activity/importstatus/viator/:supplierId/:productId` | supplier/product IDs |
| POST | `/bookings/activity/import/viator/:supplierId` | import config |
| POST | `/bookings/activity/import/viator/:supplierId/:productId` | import config |
| POST | `/viator/activities/publish/:activityId` | activity ID |
| POST | `/viator/activities/unpublish/:activityId` | activity ID |
| GET | `/viator/vendor/json` | - |
| GET | `/viator/supplier-login/import` | - |
| GET | `/dashboard/viator-import-status` | - |

---

## 9. Admin API

### Users
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/admin/users/json` | - |
| DELETE | `/admin/users/:id/delete` | user ID |
| POST | `/admin/users/:id/force-logout-reset-password` | user ID |
| POST | `/admin/users/:id/disable-mfa` | user ID |
| POST | `/admin/users/:id/remove-disguise` | user ID |

### Vendor Impersonation
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/admin/disguise/add/:vendorId` | vendor ID (admin) |
| GET | `/admin/disguise/remove` | - |
| GET | `/admin/vendors/suggest` | search query |
| GET | `/admin/vendors/:id` | vendor ID |
| GET | `/managed-vendors/suggest` | search query |
| GET | `/managed-vendors/:id/disguise` | vendor ID |
| GET | `/managed-vendors/remove-disguise` | - |

### White Labels
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/admin/white-labels` | - |
| GET | `/admin/white-labels/:id` | white label ID |
| GET | `/admin/white-labels/:id/invoice-report-status` | - |

### System
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/admin/system-settings` | - |
| GET | `/admin/system-settings/data` | - |
| GET | `/admin/plugins` | - |
| GET | `/admin/plugins/:pid` | plugin ID |
| GET | `/admin/index-options` | - |
| GET | `/admin/feature-feedback` | - |
| GET | `/admin/feature-feedback/data` | - |
| GET | `/admin/tos` | - |
| GET | `/admin/tos/:id` | TOS ID |

---

## 10. User Management API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/user-management/agents` | - |
| GET | `/user-management/roles` | - |
| GET | `/user-management/roles/:id` | role ID |
| POST | `/user-management/roles/permission` | permission data |
| GET | `/user-management/staff-domains` | - |
| GET | `/user-management/types` | - |
| GET | `/user-management/users/:id` | user ID |
| POST | `/user-management/users/:id/reset` | user ID |
| GET | `/user-management/users` | `?orderBy={e}&orderByDir={t}&query={n}&page={r}&pageSize={a}&role={i}&agentId={o}` |
| POST | `/users/set-modal-seen` | `?frontendModalType={type}` |

### User Profile
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/user-profile/details` | - |
| GET | `/user-profile/language-and-time` | - |
| GET | `/userConfig/get` | - |
| GET | `/user-info` | - |
| GET | `/profile/mfa` | - |
| POST | `/mfa/enable` | - |
| POST | `/mfa/disable` | - |

---

## 11. Vendor Management API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/vendor-public-info` | - |
| GET | `/vendor/currency-exchange-provider-options` | - |
| GET | `/vendor-management/email-settings` | - |
| GET | `/vendor-management/ticket-settings` | - |
| GET | `/vendor-management/global-settings` | - |
| GET | `/vendor-management/contact-info` | - |
| GET | `/vendor-management/company-profile` | - |
| GET | `/vendor-management/agent-settings` | - |
| GET | `/vendor-management/audit-trail-settings` | - |
| POST | `/vendor-question/:trigger/next` | trigger data |
| POST | `/vendor-question/answer` | answer data |
| POST | `/vendor-question/answer/:trigger/:questionTitle` | answer data |
| GET | `/customer-leads` | - |
| GET | `/managed-vendors/tos` | - |
| GET | `/managed-vendors/tos/:id` | TOS ID |
| GET | `/operations/booking-labels` | - |
| GET | `/operations/booking-labels/:id` | label ID |

---

## 12. Chargebee / Payment API

### Chargebee Integration
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/chargebee/billing-history` | - |
| POST | `/chargebee/coupon/:couponCode/:planId` | coupon validation |
| POST | `/chargebee/coupon/:couponCode/:subscriptionId` | coupon apply |
| GET | `/chargebee/couponoffer/` | - |
| POST | `/chargebee/couponoffer/:couponKey/claim` | claim offer |
| POST | `/chargebee/couponoffer/:couponKey/create` | create offer |
| POST | `/chargebee/create-3ds-payment-intent` | 3DS payment intent |
| POST | `/chargebee/portal-session` | portal session |
| POST | `/chargebee/update-primary-payment-method` | payment method |
| POST | `/chargebee/update-advanced-primary-payment-method` | advanced payment |

### Payment Providers
| Provider | Evidence |
|----------|----------|
| **Chargebee** | Primary payment system, card tokenization, portal |
| **PayPal** | `paypalPaymentSource.email`, PayPal button UI |
| **Credit Card** | `creditCardPaymentSource` with `brand`, `expiryMonth`, `expiryYear`, `last4` |
| **Borgun** | `borgunPaymentSource` - Icelandic payment processor |

### Checkout Flow
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| POST | `{processCheckoutEndpoint}` | Full checkout payload |
| POST | `{processRedirectBookingReceiptEndpoint}` | Redirect receipt |
| POST | `{ppcpCreateOrderEndpoint}` | PayPal order |
| POST | `/add-payment/` | - |
| POST | `/add-refund/` | - |
| POST | `/payments` | - |

---

## 13. SaaS / Subscription API

### Plans
`FREE`, `PRO`, `LITE`, `ENTERPRISE`, `START`, `PLUS`, `PREMIUM`, `EXPAND`, `RESELLER`, `FREE_RESELLER`

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/saas/subscription-status` | - |
| POST | `/saas/update-base-subscription` | subscription data |
| POST | `/saas/remove-scheduled-cancellation` | - |
| GET | `/saas/change-base-invoice-estimate/:basePlanType` | plan type |
| GET | `/saas/upcoming-invoice-estimate` | - |
| POST | `/saas/upgrade-plan` | plan data |
| POST | `/saas/change-plan` | plan data |
| GET | `/feature-gate/downgrade-display-config/:toPlan` | target plan |
| GET | `/feature-gate/analyze-downgrade-impact/:toPlan` | target plan |
| POST | `/feature-gating/validate` | validation data |

### Response Schema
```json
{
  "baseSubscriptionStatus": {
    "status": "string",
    "basePlanType": "string",
    "trialEndDate": "string",
    "scheduledCancellationDate": "string",
    "channelBookingFees": "object"
  },
  "creditCardPaymentSource": {},
  "paypalPaymentSource": {},
  "borgunPaymentSource": {},
  "featureStatuses": [],
  "availablePlans": [],
  "appInstallations": [],
  "whiteLabeledVendor": "boolean",
  "whiteLabelType": "string",
  "jtbSubVendor": "object",
  "jtb": "object"
}
```

---

## 14. Marketplace / Contracts API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/marketplace/options` | - |
| GET | `/marketplace/ota-settings` | - |
| GET | `/marketplace/get-products/:activityId` | activity ID |
| GET | `/referrals/overview` | - |
| GET | `/search` | - |
| GET | `/dashboard/promotions` | - |
| GET | `/dashboard/vendor-objectives` | - |

### Contract Navigation
- `/sales-tools/marketplace/contracts`
- `/sales-tools/marketplace/contract-terms`
- `/sales-tools/marketplace/discover`
- `/sales-tools/marketplace/conversations`
- `/sales-tools/affiliate-hub/discover`
- `/sales-tools/affiliate-hub`

### Send-to-User Notifications
| Method | Endpoint |
|--------|----------|
| POST | `/sendToUser/bookingAlert` |
| POST | `/sendToUser/departureSoldOut` |
| POST | `/sendToUser/futureAvailabilityMissing` |
| POST | `/sendToUser/futureAvailabilityMissingMoch` |
| POST | `/sendToUser/freezeContract` |
| POST | `/sendToUser/unFreezeContract` |

---

## 15. Affiliates API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/affiliates/list` | `?${query}` |
| GET | `/affiliates/json/:id` | affiliate ID |
| GET | `/affiliates/taxes` | - |
| GET | `/affiliates/sales-report/direct-access/:token` | access token |
| POST | `/affiliates/new` | affiliate data |

---

## 16. Connections / API Keys API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/connections/api-keys` | - |
| GET | `/connections/api-keys/:id` | API key ID |
| POST | `/connections/api/add-apikey` | API key data |
| DELETE | `/connections/api/:apiKeyId/delete` | API key ID |
| GET | `/connections/mcp` | - |
| POST | `/connections/mcp/add-mcp-token` | MCP token data |
| DELETE | `/connections/mcp/:apiKeyId/delete` | MCP token ID |
| GET | `/connections/webhooks` | - |
| GET | `/connections/webhooks/booking/:id` | webhook ID |
| GET | `/connections/webhooks/product/:id` | webhook ID |

---

## 17. Notification System API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/fetch-notifications/:lastId/:timestamp` | polling with cache |
| POST | `/setNotificationRead/:id` | notification ID |
| POST | `/setAllNotificationsRead` | - |
| POST | `/setNotificationsAsSeen` | - |

### Notification Types
- `BOOKING_ALERT`, `DEPARTURE_SOLD_OUT`, `FUTURE_AVAILABILITY_MISSING`
- `PRODUCT_HEALTH_CHECK`, `MARKETING_TIP`, `NEW_FEATURE_ALERT`
- `CONTRACT_TERMS_REQUESTED`, `CONTRACT_PROPOSED`, `CONTRACT_FROZEN`
- `CONTRACT_UN_FROZEN`, `AFFILIATE_HUB_TERMS_CHANGED`
- `ACTIVITY_PRICE_CHANGED`, `MARKETPLACE_MESSAGE_RECEIVED`
- `DEPENDENT_ACTIVITY_DELETED`, `VENDOR_UPDATE_FAILED`

---

## 18. Pusher WebSocket API

### Configuration
- Library: Pusher.js v7.6.0
- Auth endpoint: `POST /pusher/auth` with `{socketId, channelName}`
- User auth: `POST /pusher/user-auth`
- Channel pattern: `#server-to-user-{userId}`
- Events: `pusher:signin`, `pusher:signin_success`, `pusher_internal:watchlist_events`

---

## 19. AI Import / Katla API

### AI Import
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/ai-import/experience-overview-eligibility` | - |
| GET | `/ai-import/products/status` | - |
| GET | `/ai-import/scraped-products` | - |
| GET | `/ai-import/url-input` | - |
| GET | `/ai-import/website-import-cap` | - |

### Katla AI Agent
| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/katla/account` | - |
| GET | `/katla/apps` | - |
| GET | `/ai-agent/conversations` | - |
| GET | `/ai-agent/conversations/:conversationId` | conversation ID |

---

## 20. REST API v2.0

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/restapi/v2.0/allocations` | - |
| GET | `/restapi/v2.0/allocation/:allocationId` | allocation ID |
| GET | `/restapi/v2.0/resources` | - |
| GET | `/restapi/v2.0/resource/:resourceId` | resource ID |
| GET | `/restapi/v2.0/resource/pools` | - |
| GET | `/restapi/v2.0/resource/pool/:resourcePoolId` | pool ID |

---

## 21. Config / System API

| Method | Endpoint | Body/Params |
|--------|----------|-------------|
| GET | `/extranet-config` | - |
| GET | `/navigation/routes` | - |
| GET/POST | `/ui-config` | config data |
| GET | `/auth-urls` | - |
| GET | `/auth-urls/profile` | - |
| GET | `/register-v2/config` | - |
| GET | `/register-v2/json` | - |
| GET | `/register-v2/json/:uuid` | UUID |
| GET | `/pricing/price-schedule` | - |
| GET | `/cancellation-policies/json/list` | - |
| GET | `/location/info` | - |
| GET | `/location/place-details` | `?placeId={id}` |
| GET | `/check-auth` | `?path={path}` |
| POST | `/frontend-log` | log data |
| POST | `/track/event` | `{eventName, properties}` |
| GET | `/selectors/language` | - |
| GET | `/selectors/currency` | - |
| GET | `/selectors/timezone` | - |
| GET | `/extranet/languages` | - |
| GET | `/update-theme` | - |
| GET | `/user-attributes` | - |
| POST | `/activity-health-check` | - |

---

## 22. OTA Integrations

| OTA | Navigation Path |
|-----|-----------------|
| **Viator** | `/app/sales-tools/otas/viator`, `/sales-tools/otas/viator/settings` |
| **GetYourGuide** | `/app/sales-tools/otas/getyourguide` |
| **Trip.com** | `/sales-tools/otas/tripcom` |
| **Klook** | `/sales-tools/otas/klook` |
| **Headout** | `/sales-tools/otas/headout` |
| **Civitatis** | `/sales-tools/otas/civitatis` |
| **Airbnb** | `/sales-tools/otas/airbnb`, `/admin/airbnb` |

---

## 23. React Router Paths

### Extranet Routes (Base: `/app`)
```
/, /ai-import, /products, /products/price-schedules
/products/resource-management, /products/allocations
/products/get-started, /products/gift-cards
/bookings, /bookings/agents/booking-agents
/bookings/agents/booking-agents/:conversationId
/bookings/agents/booking-agents/:conversationId/payments
/bookings/departures, /bookings/departures/:availabilityId
/bookings/calendar, /bookings/calendar/:availabilityId
/bookings/create, /bookings/desk
/settings, /settings/connections, /settings/connections/api
/settings/connections/mcp, /settings/connections/webhooks
/settings/notifications, /settings/user-management
/settings/user-management/users, /settings/user-management/roles
/settings/affiliates, /settings/payment-providers
/settings/auto-messages, /settings/future-availability
/settings/product-extension, /settings/product-extension/pricing-categories
/settings/product-extension/offers
/settings/managed-vendors/tos, /settings/operations/labels
/partner-hub, /onboarding-hub
/katla, /katla/agent, /katla/agent/:conversationId
/operations, /operations/closeouts
/operations/pick-up, /operations/pick-up/drivers
/operations/labels
/admin, /admin/users, /admin/white-labels
/admin/tos, /admin/system-settings
/admin/plugins, /admin/index-options
/admin/feature-feedback
/admin/vendors/:vendorId/users
/admin/chargebee-subscriptions/:vendorId
/admin/bulk-upload/:vendorId
/admin/airbnb/:vendorId
/marketplace, /marketplace/profile
/marketplace/onboarding, /marketplace/intelligence
/marketplace/dashboard, /marketplace/ai-search
/sales-tools/otas/viator, /sales-tools/otas/tripcom
/sales-tools/otas/klook, /sales-tools/otas/headout
/sales-tools/otas/getyourguide, /sales-tools/otas/civitatis
/sales-tools/otas/airbnb
/experience-creation/introduction
/experience-creation/choose, /experience-creation/:productId
```

### Public Routes
```
/signup, /signin, /password/reset, /password/request
/terms-of-service, /validate-email
/payment, /pass-the-fee, /sales, /details
/create-account, /account-created
/plans/:planCode, /plan-preview/:planType
/webhooks/product/:id, /webhooks/booking/:id
/pay/:paymentIntentId, /tos/:whiteLabelType
/affiliate-report/:token
/confirmation/:confirmationCode
```

### Admin Routes
```
/admin, /admin/users, /admin/white-labels
/admin/tos, /admin/system-settings
/admin/plugins, /admin/index-options
/admin/feature-feedback
/admin/vendors/:vendorId, /admin/vendors/:vendorId/users
/admin/chargebee-subscriptions/:vendorId
/admin/bulk-upload/:vendorId
/admin/airbnb/:vendorId
/admin/airbnb/:vendorId/activityRate/:activityRateId
```

---

## 24. Security Findings

### Critical
1. **Admin impersonation**: `/admin/disguise/add/:vendorId` - vendor impersonation endpoint
2. **MFA bypass**: `/admin/users/:id/disable-mfa` - MFA disable from client
3. **Force logout**: `/admin/users/:id/force-logout-reset-password`
4. **Disguise removal**: `/admin/users/:id/remove-disguise` - impersonation cleanup

### High
5. **Google API key hardcoded**: `AIzaSyDFiCTOFiP5Yzdp0CMA8hyOmsMuyWmUvs0`
6. **Sentry DSN exposed**: Enables anyone to send events to the project
7. **CAPTCHA bypass**: IP-based `bypassCaptcha` mechanism
8. **SSRF risk**: `/check-auth?path={path}` - path parameter may not be validated

### Medium
9. **Session exposure**: `X-Bokun-Session` header in every request
10. **postMessage with `"*"` origin**: rrweb cross-origin events
11. **Dynamic payment endpoints**: `processCheckoutEndpoint`, `ppcpCreateOrderEndpoint` set server-side
12. **No CSRF tokens visible**: Cookie-based auth without visible CSRF protection

### Low
13. **localStorage for session state**: `__LSM__`, navigation state persistence
14. **Content-Type: `*/*`**: Content sniffing risk in some requests
15. **Pusher auth endpoint**: `POST /pusher/auth` accepts socketId+channelName

### Statistics
- **Total API endpoints discovered**: 250+
- **HTTP method calls**: 743 (497 GET, 131 DELETE, 62 POST, 33 fetch, 17 PATCH, 3 PUT)
- **Custom headers**: 6 X-Bokun-* headers
- **Third-party services**: 10+ (Chargebee, Pusher, Sentry, GTM, Segment, Turnstile, Intercom, Avo, rrweb, GoTo)
- **JS files analyzed**: 203 (13.1 MB total)
