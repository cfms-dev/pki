// RFC 8555 Section 6.7 Error format and problem document

export class AcmeError extends Error {
  public type: string;
  public status: number;
  public detail: string;
  public subproblems?: Array<{ type: string; detail: string; identifier?: unknown }>;

  constructor(
    type: string,
    detail: string,
    status = 400,
    subproblems?: Array<{ type: string; detail: string; identifier?: unknown }>
  ) {
    super(detail);
    this.name = "AcmeError";
    this.type = type.startsWith("urn:") ? type : `urn:ietf:params:acme:error:${type}`;
    this.status = status;
    this.detail = detail;
    this.subproblems = subproblems;
  }

  toResponse(headers: Record<string, string> = {}): Response {
    const body: Record<string, unknown> = {
      type: this.type,
      detail: this.detail,
      status: this.status,
    };
    if (this.subproblems && this.subproblems.length > 0) {
      body.subproblems = this.subproblems;
    }
    return new Response(JSON.stringify(body), {
      status: this.status,
      headers: {
        "Content-Type": "application/problem+json",
        ...headers,
      },
    });
  }

  static badNonce(detail = "The JWS sent by the client did not contain a valid replay-nonce"): AcmeError {
    return new AcmeError("badNonce", detail, 400);
  }

  static malformed(detail = "Request payload was malformed"): AcmeError {
    return new AcmeError("malformed", detail, 400);
  }

  static unauthorized(detail = "Client is not authorized"): AcmeError {
    return new AcmeError("unauthorized", detail, 403);
  }

  static notFound(detail = "The requested resource does not exist"): AcmeError {
    return new AcmeError("malformed", detail, 404);
  }

  static badCSR(detail = "The CSR was not valid"): AcmeError {
    return new AcmeError("badCSR", detail, 400);
  }

  static orderNotReady(detail = "Order is not ready for finalization"): AcmeError {
    return new AcmeError("orderNotReady", detail, 403);
  }

  static rateLimited(detail = "Rate limit exceeded"): AcmeError {
    return new AcmeError("rateLimited", detail, 429);
  }

  static rejectedIdentifier(detail = "The requested identifier is not permitted"): AcmeError {
    return new AcmeError("rejectedIdentifier", detail, 400);
  }

  static alreadyRevoked(detail = "Certificate is already revoked"): AcmeError {
    return new AcmeError("alreadyRevoked", detail, 400);
  }

  static serverInternal(detail = "Internal server error"): AcmeError {
    return new AcmeError("serverInternal", detail, 500);
  }
}
