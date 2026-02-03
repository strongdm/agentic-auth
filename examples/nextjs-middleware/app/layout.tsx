export const metadata = {
  title: "StrongDM ID Next.js Example",
  description: "Example API protected by StrongDM ID authentication",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
