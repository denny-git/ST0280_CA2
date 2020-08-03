namespace CSC_CA2.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddCol : DbMigration
    {
        public override void Up()
        {
            DropPrimaryKey("dbo.UserRecordings");
            AddColumn("dbo.UserRecordings", "FileId", c => c.String(nullable: false, maxLength: 128));
            AddColumn("dbo.UserRecordings", "TranscribedText", c => c.String());
            AddPrimaryKey("dbo.UserRecordings", "FileId");
            DropColumn("dbo.UserRecordings", "Id");
        }
        
        public override void Down()
        {
            AddColumn("dbo.UserRecordings", "Id", c => c.String(nullable: false, maxLength: 128));
            DropPrimaryKey("dbo.UserRecordings");
            DropColumn("dbo.UserRecordings", "TranscribedText");
            DropColumn("dbo.UserRecordings", "FileId");
            AddPrimaryKey("dbo.UserRecordings", "Id");
        }
    }
}
