import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const subject = request.headers.get("x-strongdm-subject");

  return NextResponse.json({
    message: "Welcome, admin!",
    agent: subject,
  });
}
