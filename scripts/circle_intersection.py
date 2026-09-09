#!/usr/bin/env python3
"""
Circle intersection computation using analytic geometry.

Given two circles with centers (x1, y1), (x2, y2) and radii r1, r2,
computes their intersection points.

Based on the problem: circle with center at origin, radius 5.
"""

import math
import sys


def circle_intersection(x1, y1, r1, x2, y2, r2):
    """
    Compute the intersection points of two circles.
    
    Returns:
        - "no_intersection" if circles don't intersect
        - "infinitely_many" if circles are identical
        - single point (x, y) if tangent
        - list of two points [(x, y), (x, y)] if intersecting
    """
    d = math.sqrt((x2 - x1)**2 + (y2 - y1)**2)
    
    # No intersection cases
    if d > r1 + r2:
        return "no_intersection"
    if d < abs(r1 - r2):
        return "no_intersection"
    # Circles are identical
    if d == 0 and r1 == r2:
        return "infinitely_many"
    
    # Compute intersection
    a = (r1**2 - r2**2 + d**2) / (2 * d)
    h = math.sqrt(max(0, r1**2 - a**2))
    
    # Point P2 is the projection of the intersection onto the line between centers
    x3 = x1 + a * (x2 - x1) / d
    y3 = y1 + a * (y2 - y1) / d
    
    # Intersection points
    rx = -((y2 - y1) * h / d) if d != 0 else 0
    ry = ((x2 - x1) * h / d) if d != 0 else 0
    
    p1 = (x3 + rx, y3 + ry)
    p2 = (x3 - rx, y3 - ry)
    
    # Check if tangent (single point)
    if h == 0:
        return [p1]
    
    return [p1, p2]


def main():
    if len(sys.argv) != 7:
        print("Usage: python circle_intersection.py x1 y1 r1 x2 y2 r2")
        sys.exit(1)
    
    try:
        x1, y1, r1 = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
        x2, y2, r2 = float(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6])
    except ValueError:
        print("Error: All arguments must be numbers")
        sys.exit(1)
    
    result = circle_intersection(x1, y1, r1, x2, y2, r2)
    
    print(f"Circle 1: center ({x1}, {y1}), radius {r1}")
    print(f"Circle 2: center ({x2}, {y2}), radius {r2}")
    print(f"Distance between centers: {math.sqrt((x2-x1)**2 + (y2-y1)**2):.4f}")
    
    if result == "no_intersection":
        print("Result: No intersection (circles don't overlap)")
    elif result == "infinitely_many":
        print("Result: Infinitely many points (circles are identical)")
    elif len(result) == 1:
        x, y = result[0]
        print(f"Result: Tangent - single intersection point: ({x:.4f}, {y:.4f})")
    else:
        x1_int, y1_int = result[0]
        x2_int, y2_int = result[1]
        print(f"Result: Two intersection points:")
        print(f"  Point 1: ({x1_int:.4f}, {y1_int:.4f})")
        print(f"  Point 2: ({x2_int:.4f}, {y2_int:.4f})")


if __name__ == "__main__":
    main()