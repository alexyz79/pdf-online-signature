using Microsoft.EntityFrameworkCore.Migrations;
using System;
using System.Collections.Generic;

namespace PDFOnlineSignature.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Reviewer",
                columns: table => new
                {
                    Uuid = table.Column<string>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    Role = table.Column<string>(type: "TEXT", nullable: false),
                    Title = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Reviewer", x => x.Uuid);
                    table.UniqueConstraint("UK_ReviewerEmail", x => x.Email);
                });

            migrationBuilder.CreateTable(
                name: "Certificate",
                columns: table => new
                {
                    Uuid = table.Column<string>(type: "TEXT", nullable: false),
                    CreationDate = table.Column<DateTime>(type: "date", nullable: true),
                    ExpireDate = table.Column<DateTime>(type: "date", nullable: true),
                    ReviewerUuid = table.Column<string>(type: "TEXT", nullable: true),
                    RevokeDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Revoked = table.Column<bool>(type: "INTEGER", nullable: true),
                    SerialNumber = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificate", x => x.Uuid);
                    table.ForeignKey(
                        name: "FK_Certificate_Reviewer_ReviewerUuid",
                        column: x => x.ReviewerUuid,
                        principalTable: "Reviewer",
                        principalColumn: "Uuid",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Document",
                columns: table => new
                {
                    Uuid = table.Column<string>(type: "TEXT", nullable: false),
                    CreationdDate = table.Column<DateTime>(type: "TEXT", nullable: false),
                    MimeType = table.Column<string>(type: "TEXT", nullable: true),
                    Name = table.Column<string>(type: "TEXT", nullable: false),
                    ReviewerUuid = table.Column<string>(type: "TEXT", nullable: true),
                    SignatureDate = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Signed = table.Column<bool>(type: "INTEGER", nullable: true),
                    Size = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Document", x => x.Uuid);
                    table.ForeignKey(
                        name: "FK_Document_Reviewer_ReviewerUuid",
                        column: x => x.ReviewerUuid,
                        principalTable: "Reviewer",
                        principalColumn: "Uuid",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CertificateRequest",
                columns: table => new
                {
                    Uuid = table.Column<string>(type: "TEXT", nullable: false),
                    CertificateUuid = table.Column<string>(type: "TEXT", nullable: true),
                    RequestDate = table.Column<DateTime>(type: "date", nullable: true),
                    ReviewerUuid = table.Column<string>(type: "TEXT", nullable: false),
                    SecurityCode = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateRequest", x => x.Uuid);
                    table.ForeignKey(
                        name: "FK_CertificateRequest_Certificate_CertificateUuid",
                        column: x => x.CertificateUuid,
                        principalTable: "Certificate",
                        principalColumn: "Uuid",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_CertificateRequest_Reviewer_ReviewerUuid",
                        column: x => x.ReviewerUuid,
                        principalTable: "Reviewer",
                        principalColumn: "Uuid",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Certificate_ReviewerUuid",
                table: "Certificate",
                column: "ReviewerUuid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequest_CertificateUuid",
                table: "CertificateRequest",
                column: "CertificateUuid");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateRequest_ReviewerUuid",
                table: "CertificateRequest",
                column: "ReviewerUuid");

            migrationBuilder.CreateIndex(
                name: "IX_Document_ReviewerUuid",
                table: "Document",
                column: "ReviewerUuid");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificateRequest");

            migrationBuilder.DropTable(
                name: "Document");

            migrationBuilder.DropTable(
                name: "Certificate");

            migrationBuilder.DropTable(
                name: "Reviewer");
        }
    }
}
