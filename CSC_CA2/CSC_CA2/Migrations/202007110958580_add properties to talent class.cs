namespace CSC_CA2.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class addpropertiestotalentclass : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.Talents", "ShortName", c => c.String());
            AddColumn("dbo.Talents", "Reknown", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.Talents", "Reknown");
            DropColumn("dbo.Talents", "ShortName");
        }
    }
}
