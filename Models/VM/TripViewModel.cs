using System.ComponentModel.DataAnnotations;

namespace aspapp.Models.VM
{
    public class TripViewModel
    {
        public int TripId { get; set; }

        [Required(ErrorMessage = "Destination is required")]
        public string Destination { get; set; }

        [Required(ErrorMessage = "Start Date is required")]
        public DateTime StartDate { get; set; }

        [Required(ErrorMessage = "Guide is required")]
        public int? GuideId { get; set; }

        [Required(ErrorMessage = "Traveler is required")]
        public int? TravelerId { get; set; }

        public IEnumerable<GuideViewModel> Guides { get; set; } = new List<GuideViewModel>();
        public IEnumerable<TravelerViewModel> Travelers { get; set; } = new List<TravelerViewModel>();

    }
}
