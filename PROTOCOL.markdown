This is an overview of the secure ATM protocol.

The design is focused entirely on security and simplicity and the expense of
performance.

# Messages

A Message is sent in a single packet of exactly 8192 bits. It contains eight
ASCII-encoded 128-character string fields. All fields are padded to *exactly*
128 bytes by appending a null character followed by random bytes. Empty or
unused fields are also filled by an initial null character followed by random
bytes.

The entire packet is encrypted with AES in CBC mode using a 256-bit shared key
amongst the Bank and ATM, then transmitted.

The first field of all packets is `MessageTypeID`, which specifies the type of
message delivered by the packet.

    +---------------+---------+---------+---------+-----+----------+----------+
    | MessageTypeID | Field 1 | Field 2 | Field 3 | ... | (unused) | HMAC Sig |
    +---------------+---------+---------+---------+-----+----------+----------+
     128 char        128 char  128 char  128 char   ...  64 char    64 char

Remember, although some descriptions and diagrams below may omit empty fields,
**all packets are padded to 8192 bits**. Each emtpy field is filled with a null
byte followed by random bytes. This prevents some forms of traffic analysis.

Packets are queued by both the ATM and Bank such that each sends exactly one
message every second. That is, both the Bank and ATM send one (and only one)
message each second. If the message queue is empty, send a NullMessage.

The following table shows `MessageTypeID`s and their corresponding message
types.

    +------+------------------+
    |  ID  | Message type     |
    +======+==================+
    |   0  | NullMessage      |
    +------+------------------+
    |  -1  | ErrorMessage     |
    +------+------------------+
    |   1  | NonceRequest     |
    +------+------------------+
    |   2  | LoginRequest     |
    +------+------------------+
    |   3  | BalanceRequest   |
    +------+------------------+
    |   4  | WithdrawRequest  |
    +------+------------------+
    |   5  | TransferRequest  |
    +------+------------------+
    |  51  | NonceResponse    |
    +------+------------------+
    |  52  | LoginResponse    |
    +------+------------------+
    |  53  | BalanceResponse  |
    +------+------------------+
    |  54  | WithdrawResponse |
    +------+------------------+
    |  55  | TransferResponse |
    +------+------------------+

## `NullMessage`

    +----+
    |  0 |
    +----+

Since the Bank and ATM both need to send exactly one message per second, they
use `NullMessage` when they have no actual data queued for sending. Since even
`NullMessage`s are encrypted, and the empty fields are each filled with a null
byte followed by random bytes, each `NullMessage` is unique and should be
indistinguishable from other encrypted messages.

## `ErrorMessage`

    +----+------------+---------------+-----------+------------+
    | -1 | Error code | Error message | ATM nonce | Bank nonce |
    +----+------------+---------------+-----------+------------+

When errors are encountered, both the Bank and ATM can send `ErrorMessage`s. If
the message relates to a Request or Response with one or more nonces, the
`ErrorMessage` will send the nonces in fields 3 and 4, otherwise they are
omitted.

The following error codes exist:

    +------+-------------------+---------+--------------------------+
    | Code | Error type        | Nonces? | Description              |
    +======+===================+=========+==========================+
    |  0   | Error             | No      | Generic or unknown error |
    +------+-------------------+---------+--------------------------+
    |  1   | RequestError      | Yes     | Generic request error    |
    +------+-------------------+---------+--------------------------+
    |  2   | LoginError        | Yes     | Bad LoginRequest         |
    +------+-------------------+---------+--------------------------+
    |  3   | AuthFailure       | Yes     | Bad auth token           |
    +------+-------------------+---------+--------------------------+
    |  4   | InsufficientFunds | Yes     | Balance too low          |
    +------+-------------------+---------+--------------------------+

## `NonceRequest` and `NonceResponse`

     NonceRequest
    +----+-----------+
    |  1 | ATM nonce |
    +----+-----------+

     NonceResponse
    +----+-----------+------------+
    | 51 | ATM nonce | Bank nonce |
    +----+-----------+------------+

All requests require nonces from both the ATM and the Bank. This is negotiated
using a `NonceRequest` from the ATM and a `NonceResponse` from the Bank.

The ATM generates 128 bytes of random data as its nonce and sends it in a
`NonceRequest` to the Bank.

When the Bank receives a `NonceRequest`, it stores the nonce it received from
the ATM along with a second 128-byte nonce that it freshly generates. It then
sends a `NonceResponse` with both nonces back to the ATM.

This nonce pair is now good for *only one request* from the ATM. In addition,
the nonce pair expires after 30 seconds.

## `LoginRequest` and `LoginResponse`

     LoginRequest
    +----+-----------+------------+----------+------+-----+
    |  2 | ATM nonce | Bank nonce | Username | Card | PIN |
    +----+-----------+------------+----------+------+-----+

     LoginResponse
    +----+-----------+------------+------------+
    | 52 | ATM nonce | Bank nonce | Auth token |
    +----+-----------+------------+------------+

The ATM can use a `LoginRequest` to exchange a user's authorization information
(username, card contents, PIN) for a 128-byte session auth token. After getting
nonces with a `NonceRequest`, the ATM sends the user's credentials to the Bank.

Upon receiving the `LoginRequest`, the Bank checks the nonces, then checks the
user's credentials. If anything's wrong, it sends an `ErrorMessage` (with the
nonces), but if all checks out, the Bank generates and stores a new 128-byte
auth token for the user and sends it over in a `LoginResponse`.

The auth token is paired with the username and expires after 5 minutes. In
addition, if a user logs into a new ATM, any other auth tokens for that user
become instantly invalid.

Unlike nonces, an auth token is good for more than one use (until it expires).

## `BalanceRequest` and `BalanceResponse`

     BalanceRequest
    +----+-----------+------------+------------+
    |  3 | ATM nonce | Bank nonce | Auth token |
    +----+-----------+------------+------------+

     BalanceResponse
    +----+-----------+------------+---------+
    | 53 | ATM nonce | Bank nonce | Balance |
    +----+-----------+------------+---------+

A user can request his or her balance through the ATM via a `BalanceRequest`.

The nonces must be generated using a `NonceRequest`, and the auth token is
generated using a `LoginRequest`.

When the Bank receives a `BalanceRequest` it checks the nonces and auth token.
If they are in order, it sends a `BalanceResponse` with the balance of the user
associated with the auth token; otherwise, it sends an `ErrorMessage` (with the
nonces).

## `WithdrawRequest` and `WithdrawResponse`

     WithdrawRequest
    +----+-----------+------------+------------+--------+
    |  4 | ATM nonce | Bank nonce | Auth token | Amount |
    +----+-----------+------------+------------+--------+

     WithdrawResponse
    +----+-----------+------------+
    | 54 | ATM nonce | Bank nonce |
    +----+-----------+------------+

A user can withdraw funds through the ATM via a `WithdrawRequest`.

The nonces must be generated using a `NonceRequest`, and the auth token is
generated using a `LoginRequest`. The request also specifies the amount to
withdraw.

When the Bank receives a `WithdrawRequest` it checks the nonces and auth token.
It also must check if the amount requested is less than or equal to the balance
of the user associated with the auth token. If everything is in order, the bank
subtracts the amount from the user's balance, saves the nonces to a transaction
log, and sends a `WithdrawResponse` indicating success; otherwise, it sends an
`ErrorMessage` with the nonces (and does **not** send a `WithdrawResponse`).

If the ATM receives a `WithdrawResponse` with correct nonces, it vends the
amount specified; if it receives an `ErrorMessage` with the correct nonces, it
tells the user to try again.

If the ATM does not receive a `WithdrawResponse` *or* an `ErrorMessage` within
30 seconds, it does **not** vend cash and instead tells the user there has been
a communication error and the ATM cannot verify if their account has been
debited.  The ATM also provides the user with a timestamped SHA512 HMAC of the
transaction (including nonces). The user can take this to a Bank office, where
an employee can then verify the HMAC against the Bank's transaction log and
give the user his or her cash. (The employee then transmits the HMAC to all
other employees so a malicious user can't reuse it.)

## `TransferRequest` and `TransferResponse`

     TransferRequest
    +----+-----------+------------+------------+-------------+--------+
    |  5 | ATM nonce | Bank nonce | Auth token | Destination | Amount |
    +----+-----------+------------+------------+-------------+--------+

     TransferResponse
    +----+-----------+------------+
    | 55 | ATM nonce | Bank nonce |
    +----+-----------+------------+

A user can transfer funds through the ATM via a `TransferRequest`.

The nonces must be generated using a `NonceRequest`, and the auth token is
generated using a `LoginRequest`. The request also specifies the destination
account and the amount to transfer.

When the Bank receives a `TransferRequest` it checks the nonces and auth token.
It also must check if the amount requested is less than or equal to the balance
of the user associated with the auth token.

(The Bank should also check that if the amount is added to the destination
user's balance, his or her new balance is still larger than both their original
balance and the transfer amount. This protects against integer overflow
attacks.)

If everything is in order, the bank subtracts the amount from the user's
balance, adds the amount to the destination balance, saves the nonces to a
transaction log, and sends a `TransferResponse` indicating success; otherwise,
it sends an `ErrorMessage` with the nonces (and does **not** send a
`TransferResponse`).

If the ATM receives a `TransferResponse` with correct nonces, it prints a
success message; if it receives an `ErrorMessage` with the correct nonces, it
tells the user to try again.

If the ATM does not receive a `TransferResponse` *or* an `ErrorMessage` within
30 seconds, it tells the user there was a communication error and it cannot
determine if the transfer completed or not. It may suggest the user check his
or her balance to determine if the transfer went through.  (Transfers are
atomic, so if the user's balance is reduced, the transfer was successful.)
