using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace aspapp.Models
{
    public class Guide
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int GuideId { get; set; }
        public string Firstname { get; set; } = string.Empty;
        public string Lastname { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Title { get; set; }

        // Kolekcja podróży przypisanych do przewodnika
        public ICollection<Trip> Trips { get; set; } = new List<Trip>(); // One-to-many relationship with Trip
    }
}
