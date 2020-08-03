namespace CSC_CA2.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class addStripeID : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.AspNetUsers", "StripeId", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.AspNetUsers", "StripeId");
        }
    }
}
