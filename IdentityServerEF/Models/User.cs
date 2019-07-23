using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerEF.Models
{
    public class User
    {
        [Column("id")]
        public int Id { get; set; }

        [Column("name")]
        public string Name { get; set; }

        [Column("password")]
        public string Password { get; set; }

        [Column("age")]
        public int Age { get; set; }

        [Column("roles")]
        public string Role { get; set; }
    }
}
