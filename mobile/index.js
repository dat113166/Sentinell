// Điểm vào app mobile. Polyfill PHẢI nạp trước lõi giao thức (@noble cần crypto.getRandomValues,
// TextEncoder/TextDecoder) — thứ tự import được Metro giữ nguyên.
import "./src/polyfills";
import { registerRootComponent } from "expo";
import App from "./App";

registerRootComponent(App);
