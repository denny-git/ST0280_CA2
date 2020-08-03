namespace CSC_CA2.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class converttotalentsmodel : DbMigration
    {
        public override void Up()
        {
            DropForeignKey("dbo.UserRecordings", "user_Id", "dbo.AspNetUsers");
            DropIndex("dbo.UserRecordings", new[] { "user_Id" });
            CreateTable(
                "dbo.Talents",
                c => new
                    {
                        Id = c.String(nullable: false, maxLength: 128),
                        Profile = c.String(),
                        Name = c.String(),
                        Url = c.String(),
                        user_Id = c.String(maxLength: 128),
                    })
                .PrimaryKey(t => t.Id)
                .ForeignKey("dbo.AspNetUsers", t => t.user_Id)
                .Index(t => t.user_Id);
            
            DropTable("dbo.UserRecordings");
        }
        
        public override void Down()
        {
            CreateTable(
                "dbo.UserRecordings",
                c => new
                    {
                        FileId = c.String(nullable: false, maxLength: 128),
                        TranscribedText = c.String(),
                        DateCreated = c.DateTime(nullable: false),
                        user_Id = c.String(maxLength: 128),
                    })
                .PrimaryKey(t => t.FileId);
            
            DropForeignKey("dbo.Talents", "user_Id", "dbo.AspNetUsers");
            DropIndex("dbo.Talents", new[] { "user_Id" });
            DropTable("dbo.Talents");
            CreateIndex("dbo.UserRecordings", "user_Id");
            AddForeignKey("dbo.UserRecordings", "user_Id", "dbo.AspNetUsers", "Id");
        }
    }
}
