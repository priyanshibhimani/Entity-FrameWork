using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ProductManagemet.Migrations
{
    public partial class PartyTotalUpdate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PartyTotal_Parties_PartyId",
                table: "PartyTotal");

            migrationBuilder.AddForeignKey(
                name: "FK_PartyTotal_Parties_PartyId",
                table: "PartyTotal",
                column: "PartyId",
                principalTable: "Parties",
                principalColumn: "PartyId",
                onDelete: ReferentialAction.Restrict);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_PartyTotal_Parties_PartyId",
                table: "PartyTotal");

            migrationBuilder.AddForeignKey(
                name: "FK_PartyTotal_Parties_PartyId",
                table: "PartyTotal",
                column: "PartyId",
                principalTable: "Parties",
                principalColumn: "PartyId",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
