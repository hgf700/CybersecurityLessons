using aspapp.Models.VM;
using aspapp.Models;
using AutoMapper;

public class TripProfile : Profile
{
    public TripProfile()
    {

        // Traveler ↔ TravelerViewModel
        CreateMap<Traveler, TravelerViewModel>().ReverseMap();
    }
}
