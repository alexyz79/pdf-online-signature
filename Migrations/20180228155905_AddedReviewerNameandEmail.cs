using Microsoft.EntityFrameworkCore.Migrations;
using System;
using System.Collections.Generic;

namespace PDFOnlineSignature.Migrations
{
    public partial class AddedReviewerNameandEmail : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ReviewerEmail",
                table: "Certificate",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ReviewerName",
                table: "Certificate",
                type: "TEXT",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ReviewerEmail",
                table: "Certificate");

            migrationBuilder.DropColumn(
                name: "ReviewerName",
                table: "Certificate");
        }
    }
}
