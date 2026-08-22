import { NextResponse } from "next/server";
import { getScanRecord, getTotalScans, getRecentScans } from "@/lib/storage";

export const runtime = "nodejs";

export async function GET() {
  const [recent, total, githubScan] = await Promise.all([
    getRecentScans(5),
    getTotalScans(),
    getScanRecord("github.com"),
  ]);

  return NextResponse.json({ total, recent, githubScan });
}
