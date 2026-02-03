import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  // Claims are added by middleware
  const subject = request.headers.get("x-strongdm-subject");
  const scopes = request.headers.get("x-strongdm-scopes")?.split(" ") || [];

  return NextResponse.json({
    message: "You are authenticated!",
    subject,
    scopes,
  });
}
