import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import * as SnapInPKI from "./snap-in-pki.js";

// Expose directly to window
if (typeof window !== "undefined") {
  window.pkijs = pkijs;
  window.asn1js = asn1js;
  window.SnapInPKI = SnapInPKI;
}

export { pkijs, asn1js, SnapInPKI };
