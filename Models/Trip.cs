using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace aspapp.Models
{
    public class Trip
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int TripId { get; set; }

        public string Destination { get; set; } = string.Empty;
        public DateTime StartDate { get; set; }
        public int? GuideId { get; set; }
        public Guide? Guide { get; set; }
        public int? TravelerId { get; set; }
        public Traveler? Traveler { get; set; }
    }
}
