using System.ComponentModel.DataAnnotations;
using aspapp.Models;
using aspapp.Models.VM;
using aspapp.Repositories;
using AutoMapper;
using Microsoft.EntityFrameworkCore;

namespace aspapp.Services
{
    public class TripService : ITripService
    {
        private readonly ITripRepository _tripRepository;
        private readonly IMapper _mapper;
        private readonly ITravelerRepository _travelerRepository;
        private readonly IGuideRepository _guideRepository;

        public TripService(
            ITripRepository tripRepository,
            IMapper mapper,
            ITravelerRepository travelerRepository,
            IGuideRepository guideRepository)
        {
            _tripRepository = tripRepository;
            _mapper = mapper;
            _travelerRepository = travelerRepository;
            _guideRepository = guideRepository;
        }


        //public async Task AddTrip(TripViewModel viewModel)
        //{
        //    if (viewModel == null)
        //        throw new ArgumentNullException(nameof(viewModel));

        //    var trip = _mapper.Map<Trip>(viewModel);
        //    await _tripRepository.AddTrip(trip);
        //}

        public async Task AddTrip(TripViewModel viewModel)
        {
            if (viewModel == null)
                throw new ArgumentNullException(nameof(viewModel));

            var guide = await _guideRepository.GetGuideById(viewModel.GuideId.Value);
            var traveler = await _travelerRepository.GetTravelerById(viewModel.TravelerId.Value);

            var trip = new Trip
            {
                Destination = viewModel.Destination,
                StartDate = viewModel.StartDate,
                GuideId = viewModel.GuideId,
                TravelerId = viewModel.TravelerId,
                //Guide=guide,
                //Traveler=traveler
            };



            await _tripRepository.AddTrip(trip);
        }


        private void ValidateTripViewModel(TripViewModel viewModel)
        {
            var context = new ValidationContext(viewModel);
            var results = new List<ValidationResult>();

            if (!Validator.TryValidateObject(viewModel, context, results, true))
                throw new ArgumentException(string.Join(", ", results.Select(r => r.ErrorMessage)));

        }

        public async Task<List<TripViewModel>> GetAllTrips()
        {
            var trips = await _tripRepository.GetAllTrips().ToListAsync();
            return trips.Select(t => _mapper.Map<TripViewModel>(t)).ToList();
        }

        public async Task<TripViewModel> GetTripById(int tripId)
        {
            var trip = await _tripRepository.GetTripById(tripId)
                ?? throw new KeyNotFoundException($"Trip with Id {tripId} not found.");
            return _mapper.Map<TripViewModel>(trip);
        }

        public async Task UpdateTrip(TripViewModel viewModel)
        {
            ValidateTripViewModel(viewModel);

            var trip = _mapper.Map<Trip>(viewModel);

            if (viewModel.GuideId.HasValue)
            {
                var guide = await _guideRepository.GetGuideById(viewModel.GuideId.Value)
                             ?? throw new KeyNotFoundException($"Guide with Id {viewModel.GuideId.Value} not found.");
                trip.Guide = guide;
                trip.GuideId = guide.GuideId;
            }

            if (viewModel.TravelerId.HasValue)
            {
                var traveler = await _travelerRepository.GetTravelerById(viewModel.TravelerId.Value)
                                 ?? throw new KeyNotFoundException($"Traveler with Id {viewModel.TravelerId.Value} not found.");
                trip.Traveler = traveler;
                trip.TravelerId = traveler.TravelerId;
            }

            await _tripRepository.UpdateTrip(trip);
        }

        public async Task DeleteTrip(int tripId)
        {
            await _tripRepository.DeleteTrip(tripId);
        }





    }
}
