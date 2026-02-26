# E-sign Providers (Broker Integration)

This package provides a provider-agnostic interface for human signature workflows.

Path: `esign/`

## Providers

- `dropbox_sign`
- `docusign`

## Capability

Each provider implements:

- Create signature request from template roles.
- Poll provider request status.
- Verify webhook authenticity.

## Go usage

```go
import "github.com/corpo/qntm/esign"

provider, err := esign.NewDropboxSignProvider(esign.DropboxSignConfig{
    APIKey: os.Getenv("DROPBOX_SIGN_API_KEY"),
})
if err != nil {
    panic(err)
}

res, err := provider.CreateSignatureRequest(ctx, esign.SignatureRequest{
    ExternalRequestID: "wire-approval-001",
    TemplateID:        "tmpl_123",
    Subject:           "Board Consent",
    Message:           "Please sign",
    Signers: []esign.Signer{
        {Name: "Alice", Email: "alice@example.com", Role: "Signer"},
    },
})
if err != nil {
    panic(err)
}
_ = res
```

## Notes

- Current request flow is template-first. Document upload flows can be added later.
- Dropbox Sign webhook verification checks `event_hash` and optionally `Content-Sha256`.
- DocuSign webhook verification checks `X-DocuSign-Signature-1` using configured HMAC secret.
