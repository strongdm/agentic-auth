// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AgentKey",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        // Vapor web framework
        .package(url: "https://github.com/vapor/vapor.git", from: "4.89.0"),
        // Fluent ORM
        .package(url: "https://github.com/vapor/fluent.git", from: "4.8.0"),
        // SQLite driver for development
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.3.0"),
        // PostgreSQL driver for production
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.8.0"),
        // JWT verification
        .package(url: "https://github.com/vapor/jwt.git", from: "4.2.0"),
        // Leaf templating engine
        .package(url: "https://github.com/vapor/leaf.git", from: "4.3.0"),
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "JWT", package: "jwt"),
                .product(name: "Leaf", package: "leaf"),
            ],
            path: "Sources/App",
            swiftSettings: [
                .unsafeFlags(["-cross-module-optimization"], .when(configuration: .release))
            ]
        ),
        .testTarget(
            name: "AppTests",
            dependencies: [
                .target(name: "App"),
                .product(name: "XCTVapor", package: "vapor"),
            ],
            path: "Tests/AppTests"
        ),
    ]
)
