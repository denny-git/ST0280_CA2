namespace CSC_CA2.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class tst : DbMigration
    {
        public override void Up()
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
                .PrimaryKey(t => t.FileId)
                .ForeignKey("dbo.AspNetUsers", t => t.user_Id)
                .Index(t => t.user_Id);
            
        }
        
        public override void Down()
        {
            DropForeignKey("dbo.UserRecordings", "user_Id", "dbo.AspNetUsers");
            DropIndex("dbo.UserRecordings", new[] { "user_Id" });
            DropTable("dbo.UserRecordings");
        }
    }
}
