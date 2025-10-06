namespace aspapp.Models
{
    public class TripTraveler
    {
        public int TripId { get; set; }
        public Trip Trip { get; set; } = null!;

        public int TravelerId { get; set; }
        public Traveler Traveler { get; set; } = null!;
    }
}
