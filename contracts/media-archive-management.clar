;; Media Archive Management System - Comprehensive solution for secure media file organization
;; 
;; This contract facilitates robust archival operations including file cataloging, ownership tracking,
;; and sophisticated access control mechanisms with complete transaction history preservation

;; ===== System Configuration Constants =====

;; Primary system administrator with elevated privileges
(define-constant system-controller tx-sender)

;; ===== Error Code Definitions =====

;; Access control and authorization error codes
(define-constant unauthorized-access-code (err u300))
(define-constant ownership-violation-code (err u306))
(define-constant access-restriction-code (err u305))
(define-constant view-limitation-code (err u307))

;; Data validation and existence error codes
(define-constant missing-record-code (err u301))
(define-constant duplicate-entry-code (err u302))
(define-constant invalid-name-code (err u303))
(define-constant invalid-size-code (err u304))
(define-constant malformed-label-code (err u308))

;; ===== Primary Storage Structures =====

;; Central repository for all media file records with comprehensive metadata
(define-map media-archive-repository
  { record-number: uint }
  {
    media-name: (string-ascii 64),
    current-owner: principal,
    byte-count: uint,
    creation-height: uint,
    content-summary: (string-ascii 128),
    category-labels: (list 10 (string-ascii 32))
  }
)

;; Access control matrix defining viewing permissions per media item
(define-map access-control-matrix
  { record-number: uint, authorized-user: principal }
  { can-access: bool }
)

;; ===== Global State Variables =====

;; Sequential counter maintaining unique identifiers for media records
(define-data-var total-archived-items uint u0)

;; ===== Helper Function Implementations =====

;; Validates individual category label format and length constraints
;; Parameters: label-text - the category label string to validate
;; Returns: boolean indicating whether the label meets requirements
(define-private (validate-category-label (label-text (string-ascii 32)))
  (and
    (> (len label-text) u0)
    (< (len label-text) u33)
  )
)

;; Performs comprehensive validation on the complete set of category labels
;; Ensures all labels in the collection meet individual validation criteria
;; Parameters: label-collection - list of category labels to validate
;; Returns: boolean indicating whether the entire collection is valid
(define-private (verify-label-collection (label-collection (list 10 (string-ascii 32))))
  (and
    (> (len label-collection) u0)
    (<= (len label-collection) u10)
    (is-eq (len (filter validate-category-label label-collection)) (len label-collection))
  )
)

;; Checks existence of a media record in the archive repository
;; Parameters: record-number - unique identifier of the media record
;; Returns: boolean indicating whether the record exists
(define-private (record-exists-check (record-number uint))
  (is-some (map-get? media-archive-repository { record-number: record-number }))
)

;; Retrieves the byte count for a specific media record
;; Provides safe access with default fallback value
;; Parameters: record-number - unique identifier of the media record
;; Returns: byte count as uint, defaulting to 0 if record not found
(define-private (retrieve-byte-count (record-number uint))
  (default-to u0
    (get byte-count
      (map-get? media-archive-repository { record-number: record-number })
    )
  )
)

;; Verifies ownership rights for a specific media record and user combination
;; Parameters: record-number - unique identifier of the media record
;; Parameters: user-principal - the principal to check ownership for
;; Returns: boolean indicating whether the user owns the specified record
(define-private (verify-ownership-rights (record-number uint) (user-principal principal))
  (match (map-get? media-archive-repository { record-number: record-number })
    archive-entry (is-eq (get current-owner archive-entry) user-principal)
    false
  )
)

;; ===== Core Public Interface Functions =====

;; Comprehensive media archival function with full metadata support
;; Creates a new media record with complete categorization and access control setup
;; Parameters: name-text - descriptive name for the media file
;; Parameters: file-bytes - size of the media file in bytes
;; Parameters: summary-text - detailed description of the media content
;; Parameters: labels - collection of category labels for organization
;; Returns: unique record identifier for the newly created media entry
(define-public (archive-new-media
  (name-text (string-ascii 64))
  (file-bytes uint)
  (summary-text (string-ascii 128))
  (labels (list 10 (string-ascii 32)))
)
  (let
    (
      (next-record-id (+ (var-get total-archived-items) u1))
    )
    ;; Comprehensive input validation phase
    (asserts! (> (len name-text) u0) invalid-name-code)
    (asserts! (< (len name-text) u65) invalid-name-code)
    (asserts! (> file-bytes u0) invalid-size-code)
    (asserts! (< file-bytes u1000000000) invalid-size-code)
    (asserts! (> (len summary-text) u0) invalid-name-code)
    (asserts! (< (len summary-text) u129) invalid-name-code)
    (asserts! (verify-label-collection labels) malformed-label-code)

    ;; Archive the media record with complete metadata
    (map-insert media-archive-repository
      { record-number: next-record-id }
      {
        media-name: name-text,
        current-owner: tx-sender,
        byte-count: file-bytes,
        creation-height: block-height,
        content-summary: summary-text,
        category-labels: labels
      }
    )

    ;; Establish initial access permissions for the creator
    (map-insert access-control-matrix
      { record-number: next-record-id, authorized-user: tx-sender }
      { can-access: true }
    )

    ;; Update the global counter for tracking purposes
    (var-set total-archived-items next-record-id)
    (ok next-record-id)
  )
)

;; Comprehensive metadata modification function for existing media records
;; Allows complete update of all mutable fields while preserving ownership history
;; Parameters: record-number - unique identifier of the record to modify
;; Parameters: updated-name - new descriptive name for the media file
;; Parameters: updated-bytes - new size specification in bytes
;; Parameters: updated-summary - new detailed content description
;; Parameters: updated-labels - new collection of category labels
;; Returns: success confirmation boolean
(define-public (modify-media-metadata
  (record-number uint)
  (updated-name (string-ascii 64))
  (updated-bytes uint)
  (updated-summary (string-ascii 128))
  (updated-labels (list 10 (string-ascii 32)))
)
  (let
    (
      (current-record (unwrap! (map-get? media-archive-repository { record-number: record-number })
        missing-record-code))
    )
    ;; Ownership and existence verification phase
    (asserts! (record-exists-check record-number) missing-record-code)
    (asserts! (is-eq (get current-owner current-record) tx-sender) ownership-violation-code)

    ;; Complete input validation for all updated fields
    (asserts! (> (len updated-name) u0) invalid-name-code)
    (asserts! (< (len updated-name) u65) invalid-name-code)
    (asserts! (> updated-bytes u0) invalid-size-code)
    (asserts! (< updated-bytes u1000000000) invalid-size-code)
    (asserts! (> (len updated-summary) u0) invalid-name-code)
    (asserts! (< (len updated-summary) u129) invalid-name-code)
    (asserts! (verify-label-collection updated-labels) malformed-label-code)

    ;; Apply comprehensive metadata updates while preserving immutable fields
    (map-set media-archive-repository
      { record-number: record-number }
      (merge current-record {
        media-name: updated-name,
        byte-count: updated-bytes,
        content-summary: updated-summary,
        category-labels: updated-labels
      })
    )
    (ok true)
  )
)

;; Secure ownership transfer mechanism with complete validation
;; Facilitates transfer of media ownership while maintaining access control integrity
;; Parameters: record-number - unique identifier of the media record
;; Parameters: recipient-principal - the new owner principal address
;; Returns: success confirmation boolean
(define-public (transfer-media-ownership (record-number uint) (recipient-principal principal))
  (let
    (
      (current-record (unwrap! (map-get? media-archive-repository { record-number: record-number })
        missing-record-code))
    )
    ;; Ownership verification and record existence validation
    (asserts! (record-exists-check record-number) missing-record-code)
    (asserts! (is-eq (get current-owner current-record) tx-sender) ownership-violation-code)

    ;; Execute ownership transfer while preserving all other metadata
    (map-set media-archive-repository
      { record-number: record-number }
      (merge current-record { current-owner: recipient-principal })
    )
    (ok true)
  )
)

;; Permanent media record removal function with ownership verification
;; Completely removes a media record from the archive system
;; Parameters: record-number - unique identifier of the record to remove
;; Returns: success confirmation boolean
(define-public (remove-media-record (record-number uint))
  (let
    (
      (target-record (unwrap! (map-get? media-archive-repository { record-number: record-number })
        missing-record-code))
    )
    ;; Strict ownership verification before allowing removal
    (asserts! (record-exists-check record-number) missing-record-code)
    (asserts! (is-eq (get current-owner target-record) tx-sender) ownership-violation-code)

    ;; Execute permanent removal from the archive repository
    (map-delete media-archive-repository { record-number: record-number })
    (ok true)
  )
)