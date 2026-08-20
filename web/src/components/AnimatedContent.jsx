/*
 * React Bits AnimatedContent, adapted for MSSOFT IP Sentinel.
 * Copyright (c) 2026 David Haz. MIT + Commons Clause License Condition v1.0.
 * License notice: ./REACT_BITS_LICENSE.md
 */
import { useEffect, useRef } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(ScrollTrigger);

export default function AnimatedContent({
  children,
  distance = 20,
  direction = "vertical",
  duration = 0.42,
  delay = 0,
  className = "",
}) {
  const ref = useRef(null);

  useEffect(() => {
    const element = ref.current;
    if (!element || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      if (element) element.style.visibility = "visible";
      return undefined;
    }

    const axis = direction === "horizontal" ? "x" : "y";
    gsap.set(element, { [axis]: distance, opacity: 0, visibility: "visible" });
    const timeline = gsap.timeline({ paused: true, delay });
    timeline.to(element, { [axis]: 0, opacity: 1, duration, ease: "power3.out" });
    const trigger = ScrollTrigger.create({
      trigger: element,
      start: "top 94%",
      once: true,
      onEnter: () => timeline.play(),
    });
    return () => {
      trigger.kill();
      timeline.kill();
    };
  }, [delay, direction, distance, duration]);

  return <div ref={ref} className={className} style={{ visibility: "hidden" }}>{children}</div>;
}
