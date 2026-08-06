import { describe, expect, test, vi } from "vitest";
import { render } from "../../../testing-library";

import Sparkline from "../../../../../../../../apps/svelte-admin/src/lib/components/ui/Sparkline.svelte";

describe("Sparkline", () => {
  test("renders placeholder div when data has fewer than 2 points", () => {
    const { container } = render(Sparkline, { props: { data: [5] } });
    const svg = container.querySelector("svg");
    expect(svg).toBeNull();
    const placeholder = container.querySelector("div > div");
    expect(placeholder).not.toBeNull();
  });

  test("renders placeholder for empty data", () => {
    const { container } = render(Sparkline, { props: { data: [] } });
    expect(container.querySelector("svg")).toBeNull();
  });

  test("renders SVG when data has 2 or more points", () => {
    const { container } = render(Sparkline, { props: { data: [10, 20, 15, 30] } });
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
  });

  test("keeps gradient ids unique across concurrent instances", () => {
    const random = vi.spyOn(Math, "random").mockReturnValue(0);
    const { container } = render(Sparkline, { props: { data: [1, 2] } });
    const second = render(Sparkline, { props: { data: [3, 4] } });
    const ids = [
      container.querySelector("linearGradient")?.getAttribute("id"),
      second.container.querySelector("linearGradient")?.getAttribute("id"),
    ];

    expect(ids[0]).toBeTruthy();
    expect(ids[1]).toBeTruthy();
    expect(new Set(ids).size).toBe(ids.length);
    random.mockRestore();
  });

  test("SVG has correct default dimensions", () => {
    const { container } = render(Sparkline, { props: { data: [1, 2, 3] } });
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
    expect(svg!.getAttribute("width")).toBe("120");
    expect(svg!.getAttribute("height")).toBe("32");
  });

  test("SVG respects custom width and height", () => {
    const { container } = render(Sparkline, {
      props: { data: [1, 2], width: 200, height: 50 },
    });
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
    expect(svg!.getAttribute("width")).toBe("200");
    expect(svg!.getAttribute("height")).toBe("50");
  });

  test("renders line path and area path", () => {
    const { container } = render(Sparkline, { props: { data: [5, 10, 3, 8] } });
    const paths = container.querySelectorAll("path");
    expect(paths.length).toBe(2);
  });

  test("area path has fill referencing gradient", () => {
    const { container } = render(Sparkline, { props: { data: [5, 10] } });
    const paths = container.querySelectorAll("path");
    const areaPath = paths[0];
    const fill = areaPath?.getAttribute("fill");
    expect(fill).toMatch(/^url\(#sparkline-grad-/);
  });

  test("line path has stroke and no fill", () => {
    const { container } = render(Sparkline, { props: { data: [5, 10] } });
    const paths = container.querySelectorAll("path");
    const linePath = paths[1];
    expect(linePath?.getAttribute("fill")).toBe("none");
    expect(linePath?.getAttribute("stroke")).toBeTruthy();
  });

  test("renders defs with linearGradient", () => {
    const { container } = render(Sparkline, { props: { data: [1, 2, 3] } });
    const gradient = container.querySelector("linearGradient");
    expect(gradient).not.toBeNull();
  });

  test("handles uniform data without error", () => {
    const { container } = render(Sparkline, { props: { data: [5, 5, 5, 5] } });
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
    const paths = container.querySelectorAll("path");
    expect(paths.length).toBe(2);
  });
});
