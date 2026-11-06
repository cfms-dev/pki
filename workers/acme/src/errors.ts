// RFC 8555 Section 6.7 Error format and problem document

export class AcmeError extends Error {
  public type: string;
  public status: number;
  public detail: string;
  public subproblems?: Array<{ type: string; detail: string; identifier?: unknown }>;
  public instance?: string;
  public extraHeaders?: Record<string, string>;
  public termsOfService?: string;

  constructor(
    type: string,
    detail: string,
    status = 400,
    subproblems?: Array<{ type: string; detail: string; identifier?: unknown }>,
    instance?: string,
    extraHeaders?: Record<string, string>,
    termsOfService?: string
  ) {
    super(detail);
    this.name = "AcmeError";
    this.type = type.startsWith("urn:") ? type : `urn:ietf:params:acme:error:${type}`;
    this.status = status;
    this.detail = detail;
    this.subproblems = subproblems;
    this.instance = instance;
    this.extraHeaders = extraHeaders;
    this.termsOfService = termsOfService;
  }

  toResponse(headers: Record<string, string> = {}): Response {
    const body: Record<string, unknown> = {
      type: this.type,
      detail: this.detail,
      status: this.status,
    };
    if (this.instance) {
      body.instance = this.instance;
    }
    if (this.termsOfService) {
      body.termsOfService = this.termsOfService;
    }
    if (this.subproblems && this.subproblems.length > 0) {
      body.subproblems = this.subproblems;
    }

    const mergedHeaders = new Headers(headers);
    mergedHeaders.set("Content-Type", "application/problem+json");

    if (this.extraHeaders) {
      for (const [k, v] of Object.entries(this.extraHeaders)) {
        if (k.toLowerCase() === "link" && mergedHeaders.has("link")) {
          mergedHeaders.append("link", v);
        } else {
          mergedHeaders.set(k, v);
        }
      }
    }

    return new Response(JSON.stringify(body, null, 2), {
      status: this.status,
      headers: mergedHeaders,
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

  static userActionRequired(
    detail = "Terms of service must be agreed to",
    termsOfServiceUrl?: string
  ): AcmeError {
    const extraHeaders: Record<string, string> = {};
    if (termsOfServiceUrl) {
      extraHeaders["Link"] = `<${termsOfServiceUrl}>;rel="terms-of-service"`;
    }
    return new AcmeError(
      "userActionRequired",
      detail,
      403,
      undefined,
      termsOfServiceUrl,
      extraHeaders,
      termsOfServiceUrl
    );
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

  static unsupportedIdentifier(
    detail = "The requested identifier type is not supported"
  ): AcmeError {
    return new AcmeError("unsupportedIdentifier", detail, 400);
  }

  static caa(detail = "Certification Authority Authorization (CAA) records forbid the CA from issuing"): AcmeError {
    return new AcmeError("caa", detail, 403);
  }

  static alreadyRevoked(detail = "Certificate is already revoked"): AcmeError {
    return new AcmeError("alreadyRevoked", detail, 400);
  }

  static serverInternal(detail = "Internal server error"): AcmeError {
    return new AcmeError("serverInternal", detail, 500);
  }
}
