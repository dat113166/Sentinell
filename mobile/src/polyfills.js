// Polyfill cho Hermes (React Native) để lõi @sentinell/core (@noble) chạy được y hệt trên PC/web.
import * as ExpoCrypto from "expo-crypto";

// crypto.getRandomValues — nguồn ngẫu nhiên đạt chuẩn mật mã của hệ điều hành (qua expo-crypto).
if (typeof globalThis.crypto === "undefined") globalThis.crypto = {};
if (typeof globalThis.crypto.getRandomValues !== "function") {
  globalThis.crypto.getRandomValues = (arr) => ExpoCrypto.getRandomValues(arr);
}

// TextEncoder/TextDecoder — Hermes mới đã có; bản cũ thì bù bằng fast-text-encoding.
if (typeof globalThis.TextEncoder === "undefined" || typeof globalThis.TextDecoder === "undefined") {
  require("fast-text-encoding");
}
