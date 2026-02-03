import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  const subject = request.headers.get("x-strongdm-subject");

  return NextResponse.json({
    message: "Share creation would happen here",
    agent: subject,
  });
}

export async function GET(request: NextRequest) {
  return NextResponse.json({
    shares: [],
    message: "This is where shares would be listed",
  });
}
