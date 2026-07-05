# GraphQL vs REST API Comparison

## Summary

| API | Operations | Auth | Introspection |
|-----|------------|------|---------------|
| **GraphQL** | 76 (38 queries + 38 mutations) | Access Token | **OPEN** |
| **REST** | 267 endpoints | Cookie/API Key | N/A |

---

## GraphQL Unique Operations (NOT in REST)

### Queries (32)
| Query | Description | IDOR Potential |
|-------|-------------|----------------|
| `booking(id)` | Get any booking by ID | HIGH |
| `experienceBooking(id)` | Get any experience booking | HIGH |
| `experienceBookingByConfirmationCode(code)` | Lookup by confirmation code | HIGH |
| `customer(id)` | Get any customer | HIGH |
| `vendorUser(id)` | Get any vendor user | HIGH |
| `node(id)` | Generic object lookup | CRITICAL |
| `restApiCredentials` | Get REST API access key | CRITICAL |
| `users(id)` | Get any user | HIGH |
| `checkout(id)` | Get any checkout | HIGH |
| `scanTicketBarcode(code)` | Scan ticket barcode | HIGH |
| `upsellProducts(bookingHash)` | Get upsell products | MEDIUM |
| `getAvailabilitiesForRescheduling(bookingHash)` | Get rescheduling data | MEDIUM |
| `experienceAvailability` | Get availability data | LOW |
| `departures` | Get departures | LOW |
| `pickups` | Get pickups | LOW |

### Mutations (38)
| Mutation | Description | Impact |
|----------|-------------|--------|
| `makePayment` | Add payment to booking | CRITICAL |
| `checkoutComplete` | Complete a checkout | CRITICAL |
| `experienceBookingCancelByVendor` | Cancel any booking | HIGH |
| `experienceBookingCancelByCustomer` | Cancel as customer | HIGH |
| `experienceUpdate` | Update any experience | HIGH |
| `experienceCreate` | Create new experience | HIGH |
| `experienceDeactivate` | Deactivate any experience | HIGH |
| `customerUpdate` | Update any customer | HIGH |
| `bookingInfoUpdate` | Update booking info | HIGH |
| `checkoutCreate` | Create new checkout | MEDIUM |
| `checkoutReserve` | Reserve availability | MEDIUM |
| `experienceRateCreate` | Create experience rate | MEDIUM |
| `experienceRateUpdate` | Update experience rate | MEDIUM |
| `experienceRateDelete` | Delete experience rate | MEDIUM |
| `addGiftCardToBooking` | Add gift card payment | MEDIUM |
| `checkoutGiftCardAppend` | Append gift card to checkout | MEDIUM |
| `checkoutPromoCodeApply` | Apply promo code | MEDIUM |
| `initiatePayment` | Create payment intent | HIGH |
| `createPaymentIntentForActivity` | Create payment intent for activity | HIGH |
| `terminalSendInvoice` | Send invoice via email | MEDIUM |
| `experienceStartTimeCreate` | Create start time | MEDIUM |
| `experienceStartTimeUpdate` | Update start time | MEDIUM |
| `experienceStartTimeDelete` | Delete start time | MEDIUM |
| `addNoteToExperienceBooking` | Add note to booking | LOW |
| `experienceBookingUpdateArrivalStatus` | Update arrival status | LOW |
| `answerBookingQuestions` | Answer booking questions | LOW |
| `updateAppSettings` | Update app settings | LOW |
| `addExtrasToExperienceBooking` | Add extras to booking | LOW |
| `checkoutExperienceBookingsAdd` | Add experiences to checkout | LOW |
| `checkoutExperienceBookingsRemove` | Remove experiences from checkout | LOW |
| `checkoutCustomerUpdate` | Update checkout customer | LOW |
| `checkoutAttributesUpdate` | Update checkout attributes | LOW |
| `checkoutPromoCodeRemove` | Remove promo code | LOW |
| `checkoutGiftCardRemove` | Remove gift card | LOW |
| `experienceBookingRescheduleByCustomer` | Reschedule as customer | LOW |
| `experienceBookingByConfirmationCode` | Lookup by confirmation code | LOW |
| `terminalReaderPresenceChannelAuthentication` | Terminal auth | LOW |

---

## REST Unique Endpoints (NOT in GraphQL)

### Activity Management (15)
- `/activities/editor/activity-options`
- `/activities/editor/create`
- `/activities/editor/:id`
- `/activities/editor/:id/update-milestone`
- `/activities/editor/:aid/publish`
- `/activities/editor/:aid/unpublish`
- `/activities/editor/config/:id`
- `/products/activities/:id/pre-delete`
- `/activities/editor/starttimes/:aid/create`
- `/activities/editor/starttimes/:id/update`
- `/activities/editor/starttimes/:id/delete`
- `/activities/editor/rates`
- `/activities/editor/rate-clone`
- `/activities/editor/rates-extras`
- `/activities/editor/extras`

### Bookings (3)
- `/booking.json/list`
- `/booking.json/:id`
- `/booking-area/booking-questions`

### Products (3)
- `/products/activities/json`
- `/products/activities/:id`
- `/products/product-lists/json`

### Vendor Management (4)
- `/vendor-management/email-settings`
- `/vendor-management/contact-info`
- `/vendor-management/global-settings`
- `/vendor-management/company-profile`

### User Management (2)
- `/user-management/agents`
- `/user-management/roles`

### Connections (1)
- `/connections/api-keys`

### SaaS (1)
- `/saas/subscription-status`

### Admin (3)
- `/admin/users/json`
- `/admin/white-labels`
- `/admin/disguise/add/:vendorId`

### Checkout (2)
- `/widgets/:uuid/checkout/create`
- `/widgets/:uuid/checkout/complete`

### Other (2)
- `/marketplace/options`
- `/affiliates/list`

---

## Security Analysis

### GraphQL Vulnerabilities
1. **Introspection Open** - Full schema exposed without auth
2. **IDOR on `node(id)`** - Generic object lookup by ID
3. **IDOR on `booking(id)`** - Can fetch any booking
4. **IDOR on `customer(id)`** - Can fetch any customer
5. **`restApiCredentials`** - Exposes REST API keys
6. **`makePayment`** - Can add payments to bookings
7. **`experienceBookingCancelByVendor`** - Can cancel any booking

### REST Vulnerabilities
1. **CSRF on API key creation** - No CSRF protection
2. **Mass assignment** - Can set role field
3. **Secret key exposure** - Exposed in responses
4. **Admin impersonation** - `/admin/disguise/add/:vendorId`

### Combined Attack Surface
- **GraphQL**: 76 operations (checkout/payment flow)
- **REST**: 267 endpoints (admin/vendor management)
- **Total**: 343 attack vectors

---

## Recommendations
1. Disable GraphQL introspection in production
2. Add auth to GraphQL data queries
3. Implement IDOR checks on all ID-based queries
4. Add rate limiting to payment mutations
5. Audit `restApiCredentials` query access
