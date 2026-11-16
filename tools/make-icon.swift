// Generates the app icon master (1024x1024 PNG). Usage: swift tools/make-icon.swift out.png
import AppKit
import CoreGraphics

let size = 1024
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icon-1024.png"
let cs = CGColorSpaceCreateDeviceRGB()
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!

func color(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(red: CGFloat((hex >> 16) & 255) / 255, green: CGFloat((hex >> 8) & 255) / 255, blue: CGFloat(hex & 255) / 255, alpha: a)
}
func gradient(_ top: UInt32, _ bottom: UInt32) -> CGGradient {
    CGGradient(colorsSpace: cs, colors: [color(top), color(bottom)] as CFArray, locations: [0, 1])!
}
func rounded(_ r: CGRect, _ radius: CGFloat) -> CGPath { CGPath(roundedRect: r, cornerWidth: radius, cornerHeight: radius, transform: nil) }

// 1. Tile (macOS icon grid: 824pt square centered in 1024) with drop shadow
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 28, color: color(0x000000, 0.35))
ctx.addPath(rounded(tile, 185)); ctx.setFillColor(color(0x1F4FBF)); ctx.fillPath()
ctx.restoreGState()
ctx.saveGState()
ctx.addPath(rounded(tile, 185)); ctx.clip()
ctx.drawLinearGradient(gradient(0x4C93FF, 0x1A3FA8), start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
// soft top highlight
ctx.drawLinearGradient(CGGradient(colorsSpace: cs, colors: [color(0xFFFFFF, 0.28), color(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!,
                       start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 640), options: [])
ctx.restoreGState()

// 2. Padlock (single, centered)
let body = CGRect(x: 272, y: 262, width: 480, height: 320)
let cx: CGFloat = 512
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 24, color: color(0x000000, 0.35))
// shackle
ctx.setStrokeColor(color(0xFFFFFF)); ctx.setLineWidth(64); ctx.setLineCap(.butt)
ctx.move(to: CGPoint(x: cx - 120, y: body.maxY - 10))
ctx.addLine(to: CGPoint(x: cx - 120, y: body.maxY + 90))
ctx.addArc(center: CGPoint(x: cx, y: body.maxY + 90), radius: 120, startAngle: .pi, endAngle: 0, clockwise: true)
ctx.addLine(to: CGPoint(x: cx + 120, y: body.maxY - 10))
ctx.strokePath()
// body
ctx.addPath(rounded(body, 70)); ctx.setFillColor(color(0xFFFFFF)); ctx.fillPath()
ctx.restoreGState()
ctx.saveGState()
ctx.addPath(rounded(body, 70)); ctx.clip()
ctx.drawLinearGradient(gradient(0xFFFFFF, 0xD9E5FA), start: CGPoint(x: cx, y: body.maxY), end: CGPoint(x: cx, y: body.minY), options: [])
ctx.restoreGState()
// envelope flap: one clean V, as on a real envelope (width : height = 3 : 2)
ctx.saveGState()
ctx.addPath(rounded(body, 70)); ctx.clip()
ctx.setLineCap(.round); ctx.setLineJoin(.round)
ctx.setStrokeColor(color(0x1F4FBF, 0.9)); ctx.setLineWidth(22)
ctx.move(to: CGPoint(x: body.minX + 50, y: body.maxY - 52))
ctx.addLine(to: CGPoint(x: cx, y: body.midY - 6))
ctx.addLine(to: CGPoint(x: body.maxX - 50, y: body.maxY - 52))
ctx.strokePath()
ctx.restoreGState()

let img = ctx.makeImage()!
let rep = NSBitmapImageRep(cgImage: img)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
