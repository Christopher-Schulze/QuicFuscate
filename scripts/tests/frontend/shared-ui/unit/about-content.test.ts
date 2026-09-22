import { describe, expect, test } from "vitest";
import { render, screen } from "./testing-library";

import AboutContent from "../../../../../packages/ui/AboutContent.svelte";

const defaultProps = {
  version: "0.2.0",
  logoSrc: "/logo.png",
};

describe("AboutContent", () => {
  test("renders QuicFuscate heading", () => {
    render(AboutContent, { props: defaultProps });
    expect(screen.getByText("QuicFuscate")).not.toBeNull();
  });

  test("renders version string", () => {
    render(AboutContent, { props: { ...defaultProps, version: "1.5.3" } });
    expect(screen.getByText("1.5.3")).not.toBeNull();
  });

  test("renders project description", () => {
    render(AboutContent, { props: defaultProps });
    expect(screen.getByText("Open-source obfuscated QUIC tunnel")).not.toBeNull();
  });

  test("renders spec entries (Engine, Protocol, Cipher, etc.)", () => {
    render(AboutContent, { props: defaultProps });
    expect(screen.getByText("Engine")).not.toBeNull();
    expect(screen.getByText("Rust + Tokio")).not.toBeNull();
    expect(screen.getByText("Protocol")).not.toBeNull();
    expect(screen.getByText("Custom QUIC v1 [RFC 9000]")).not.toBeNull();
    expect(screen.getByText("Cipher")).not.toBeNull();
    expect(screen.getByText("AES-128-GCM | AEGIS-128L")).not.toBeNull();
  });

  test("renders CPU features when provided", () => {
    render(AboutContent, {
      props: { ...defaultProps, cpuFeatures: ["AES-NI", "AVX2", "SSE4.2"] },
    });
    expect(screen.getByText("CPU Features")).not.toBeNull();
    expect(screen.getByText("AES-NI")).not.toBeNull();
    expect(screen.getByText("AVX2")).not.toBeNull();
    expect(screen.getByText("SSE4.2")).not.toBeNull();
  });

  test("does not render CPU features section when array is empty", () => {
    const { container } = render(AboutContent, {
      props: { ...defaultProps, cpuFeatures: [] },
    });
    const cpuHeading = container.querySelector("p");
    const allText = container.textContent ?? "";
    expect(allText).not.toContain("CPU Features");
  });

  test("renders error message instead of specs when error is provided", () => {
    render(AboutContent, {
      props: { ...defaultProps, error: "Failed to load info" },
    });
    expect(screen.getByText("Failed to load info")).not.toBeNull();
  });
});
