;; Payment Security and Fraud Prevention Smart Contract
;; Built with Clarinet for Stacks blockchain

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INSUFFICIENT_FUNDS (err u101))
(define-constant ERR_PAYMENT_FROZEN (err u102))
(define-constant ERR_FRAUD_DETECTED (err u103))
(define-constant ERR_INVALID_AMOUNT (err u104))
(define-constant ERR_RATE_LIMIT_EXCEEDED (err u105))
(define-constant ERR_BLACKLISTED (err u106))
(define-constant ERR_INVALID_RECIPIENT (err u107))

;; Data Variables
(define-data-var contract-owner principal CONTRACT_OWNER)
(define-data-var fraud-detection-enabled bool true)
(define-data-var max-transaction-amount uint u10000000) ;; 10M microSTX
(define-data-var daily-limit uint u50000000) ;; 50M microSTX per day
(define-data-var rate-limit-window uint u86400) ;; 24 hours in seconds
(define-data-var current-day-counter uint u0) ;; Manual day counter
(define-data-var last-day-update uint u0) ;; Last update timestamp

;; Data Maps
(define-map user-balances principal uint)
(define-map frozen-accounts principal bool)
(define-map blacklisted-addresses principal bool)
(define-map transaction-history 
  { user: principal, day: uint } 
  { amount: uint, count: uint })
(define-map suspicious-activity 
  principal 
  { score: uint, last-update: uint })
(define-map authorized-merchants principal bool)
(define-map payment-escrow 
  { sender: principal, recipient: principal, nonce: uint }
  { amount: uint, timestamp: uint, released: bool })

;; Private Functions

;; Simple day counter - just returns the manual counter
(define-private (safe-get-current-day)
  (var-get current-day-counter)
)

;; Generate a simple pseudo-random number using basic math
(define-private (get-pseudo-random (seed uint))
  (+ seed (var-get current-day-counter))
)

;; Calculate fraud risk score based on transaction patterns
(define-private (calculate-fraud-score (user principal) (amount uint))
  (let (
    (current-activity (default-to { score: u0, last-update: u0 } 
                     (map-get? suspicious-activity user)))
    (current-day (safe-get-current-day))
    (daily-stats (default-to { amount: u0, count: u0 } 
                 (map-get? transaction-history { user: user, day: current-day })))
  )
    (+ 
      ;; Base score from amount (higher amounts = higher risk)
      (/ amount u100000)
      ;; Frequency penalty (too many transactions)
      (* (get count daily-stats) u5)
      ;; Large amount penalty
      (if (> amount (var-get max-transaction-amount)) u50 u0)
      ;; Historical suspicious activity
      (get score current-activity)
    )
  )
)

;; Update transaction history for rate limiting
(define-private (update-transaction-history (user principal) (amount uint))
  (let (
    (current-day (safe-get-current-day))
    (existing-stats (default-to { amount: u0, count: u0 } 
                    (map-get? transaction-history { user: user, day: current-day })))
  )
    (map-set transaction-history 
      { user: user, day: current-day }
      { 
        amount: (+ (get amount existing-stats) amount),
        count: (+ (get count existing-stats) u1)
      }
    )
  )
)
;; Check if user exceeds daily limits
(define-private (check-daily-limits (user principal) (amount uint))
  (let (
    (current-day (safe-get-current-day))
    (daily-stats (default-to { amount: u0, count: u0 } 
                 (map-get? transaction-history { user: user, day: current-day })))
  )
    (<= (+ (get amount daily-stats) amount) (var-get daily-limit))
  )
)

;; Validate transaction security
(define-private (validate-transaction (sender principal) (recipient principal) (amount uint))
  (and 
    ;; Check if sender is not frozen
    (not (default-to false (map-get? frozen-accounts sender)))
    ;; Check if recipient is not blacklisted
    (not (default-to false (map-get? blacklisted-addresses recipient)))
    ;; Check amount is valid
    (> amount u0)
    ;; Check daily limits
    (check-daily-limits sender amount)
    ;; Check if fraud detection passes
    (or 
      (not (var-get fraud-detection-enabled))
      (< (calculate-fraud-score sender amount) u100) ;; Fraud score threshold
    )
  )
)

;; Public Functions

;; Initialize user balance
(define-public (deposit (amount uint))
  (let (
    (current-balance (default-to u0 (map-get? user-balances tx-sender)))
  )
    (begin
      (asserts! (> amount u0) ERR_INVALID_AMOUNT)
      (map-set user-balances tx-sender (+ current-balance amount))
      (ok true)
    )
  )
)
;; Secure payment function with fraud detection
(define-public (secure-payment (recipient principal) (amount uint))
  (let (
    (sender-balance (default-to u0 (map-get? user-balances tx-sender)))
    (recipient-balance (default-to u0 (map-get? user-balances recipient)))
  )
    (begin
      ;; Validate transaction
      (asserts! (validate-transaction tx-sender recipient amount) ERR_FRAUD_DETECTED)
      (asserts! (>= sender-balance amount) ERR_INSUFFICIENT_FUNDS)
      (asserts! (not (is-eq tx-sender recipient)) ERR_INVALID_RECIPIENT)
      
      ;; Update balances
      (map-set user-balances tx-sender (- sender-balance amount))
      (map-set user-balances recipient (+ recipient-balance amount))
      
      ;; Update transaction history
      (update-transaction-history tx-sender amount)
      
      ;; Update fraud score if suspicious
      (let ((fraud-score (calculate-fraud-score tx-sender amount)))
        (if (> fraud-score u50)
          (map-set suspicious-activity tx-sender 
            { score: fraud-score, last-update: (safe-get-current-day) })
          true
        )
      )
      
      (ok { sender: tx-sender, recipient: recipient, amount: amount })
    )
  )
)

;; Escrow payment for high-value transactions
(define-public (create-escrow (recipient principal) (amount uint) (nonce uint))
  (let (
    (sender-balance (default-to u0 (map-get? user-balances tx-sender)))
    (escrow-key { sender: tx-sender, recipient: recipient, nonce: nonce })
  )
    (begin
      (asserts! (>= sender-balance amount) ERR_INSUFFICIENT_FUNDS)
      (asserts! (validate-transaction tx-sender recipient amount) ERR_FRAUD_DETECTED)
      (asserts! (is-none (map-get? payment-escrow escrow-key)) (err u108)) ;; Escrow exists
      
      ;; Lock funds in escrow
      (map-set user-balances tx-sender (- sender-balance amount))
      (map-set payment-escrow escrow-key 
        { amount: amount, timestamp: (safe-get-current-day), released: false })
      
      (ok escrow-key)
    )
  )
)

;; Release escrow payment
(define-public (release-escrow (sender principal) (recipient principal) (nonce uint))
  (let (
    (escrow-key { sender: sender, recipient: recipient, nonce: nonce })
    (escrow-data (unwrap! (map-get? payment-escrow escrow-key) (err u109)))
    (recipient-balance (default-to u0 (map-get? user-balances recipient)))
  )
    (begin
      ;; Only sender or contract owner can release
      (asserts! (or (is-eq tx-sender sender) (is-eq tx-sender (var-get contract-owner))) 
                ERR_UNAUTHORIZED)
      (asserts! (not (get released escrow-data)) (err u110)) ;; Already released
      
      ;; Release funds
      (map-set user-balances recipient 
        (+ recipient-balance (get amount escrow-data)))
      (map-set payment-escrow escrow-key 
        (merge escrow-data { released: true }))
      
      (ok true)
    )
  )
)

;; Admin Functions (Contract Owner Only)
;; Freeze suspicious account
(define-public (freeze-account (account principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (map-set frozen-accounts account true)
    (ok true)
  )
)

;; Unfreeze account
(define-public (unfreeze-account (account principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (map-delete frozen-accounts account)
    (ok true)
  )
)

;; Add to blacklist
(define-public (blacklist-address (address principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (map-set blacklisted-addresses address true)
    (ok true)
  )
)

;; Remove from blacklist
(define-public (whitelist-address (address principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (map-delete blacklisted-addresses address)
    (ok true)
  )
)

;; Update fraud detection settings
(define-public (toggle-fraud-detection)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set fraud-detection-enabled (not (var-get fraud-detection-enabled)))
    (ok (var-get fraud-detection-enabled))
  )
)

;; Update day counter manually (admin function)
(define-public (advance-day-counter)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set current-day-counter (+ (var-get current-day-counter) u1))
    (ok (var-get current-day-counter))
  )
)

;; Update transaction limits
(define-public (update-max-transaction-amount (new-amount uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set max-transaction-amount new-amount)
    (ok true)
  )
)

;; Read-only Functions

;; Get user balance
(define-read-only (get-balance (user principal))
  (default-to u0 (map-get? user-balances user))
)

;; Check if account is frozen
(define-read-only (is-account-frozen (account principal))
  (default-to false (map-get? frozen-accounts account))
)

;; Check if address is blacklisted
(define-read-only (is-blacklisted (address principal))
  (default-to false (map-get? blacklisted-addresses address))
)

;; Get fraud score for user
(define-read-only (get-fraud-score (user principal) (amount uint))
  (calculate-fraud-score user amount)
)

;; Get daily transaction stats
(define-read-only (get-daily-stats (user principal))
  (let (
    (current-day (safe-get-current-day))
  )
    (default-to { amount: u0, count: u0 } 
                (map-get? transaction-history { user: user, day: current-day }))
  )
)

;; Get escrow details
(define-read-only (get-escrow-details (sender principal) (recipient principal) (nonce uint))
  (map-get? payment-escrow { sender: sender, recipient: recipient, nonce: nonce })
)

;; Get contract settings
(define-read-only (get-contract-settings)
  {
    fraud-detection-enabled: (var-get fraud-detection-enabled),
    max-transaction-amount: (var-get max-transaction-amount),
    daily-limit: (var-get daily-limit),
    contract-owner: (var-get contract-owner)
  }
)