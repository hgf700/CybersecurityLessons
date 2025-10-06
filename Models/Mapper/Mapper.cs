using aspapp.Models.VM;
using aspapp.Models;
using AutoMapper;

public class TripProfile : Profile
{
    public TripProfile()
    {
        // Trip → TripViewModel
        CreateMap<Trip, TripViewModel>()
            .ForMember(dest => dest.Guides, opt => opt.Ignore())     // te listy są ładowane osobno
            .ForMember(dest => dest.Travelers, opt => opt.Ignore());

        // TripViewModel → Trip
        CreateMap<TripViewModel, Trip>()
            .ForMember(dest => dest.Guide, opt => opt.Ignore())     // obiekty Guide/Traveler nie są mapowane
            .ForMember(dest => dest.Traveler, opt => opt.Ignore());

        // Guide ↔ GuideViewModel
        CreateMap<Guide, GuideViewModel>().ReverseMap()
            .ForMember(dest => dest.Trips, opt => opt.Ignore()); // zapobiega cyklom

        // Traveler ↔ TravelerViewModel
        CreateMap<Traveler, TravelerViewModel>().ReverseMap()
            .ForMember(dest => dest.Trips, opt => opt.Ignore()); // zapobiega cyklom
    }
}
