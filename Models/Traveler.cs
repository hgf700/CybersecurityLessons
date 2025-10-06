using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace aspapp.Models
{
    public class Traveler
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int TravelerId { get; set; }
        public string Firstname { get; set; } = string.Empty;
        public string Lastname { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public DateTime BirthDate { get; set; }

        // Kolekcja podróży związanych z podróżnikiem
        public ICollection<Trip> Trips { get; set; } = new List<Trip>(); // Many-to-many relationship with Trip
    }
}
