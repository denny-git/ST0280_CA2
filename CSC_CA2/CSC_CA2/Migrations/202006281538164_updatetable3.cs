namespace CSC_CA2.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class updatetable3 : DbMigration
    {
        public override void Up()
        {
            DropForeignKey("dbo.UserRecordings", "user_Id", "dbo.AspNetUsers");
            DropIndex("dbo.UserRecordings", new[] { "user_Id" });
            DropTable("dbo.UserRecordings");
        }
        
        public override void Down()
        {
            CreateTable(
                "dbo.UserRecordings",
                c => new
                    {
                        Id = c.String(nullable: false, maxLength: 128),
                        DateCreated = c.DateTime(nullable: false),
                        user_Id = c.String(maxLength: 128),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateIndex("dbo.UserRecordings", "user_Id");
            AddForeignKey("dbo.UserRecordings", "user_Id", "dbo.AspNetUsers", "Id");
        }
    }
}
