using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using aspapp.Models;
using aspapp.Repositories;
using AutoMapper;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using aspapp.Models.VM;

namespace aspapp.Services
{
    public class TravelerService : ITravelerService
    {
        private readonly ITravelerRepository _travelerRepository;
        private readonly IMapper _mapper;

        public TravelerService(ITravelerRepository travelerRepository, IMapper mapper)
        {
            _travelerRepository = travelerRepository;
            _mapper = mapper;
        }

        // Pobieranie wszystkich podróżników
        public async Task<List<TravelerViewModel>> GetAllTravelers()
        {
            return await _travelerRepository.GetAllTravelers()
                                          .Select(traveler => _mapper.Map<TravelerViewModel>(traveler))
                                          .ToListAsync(); // Ensure it’s a List
        }

        // Pobieranie podróżnika po ID
        public async Task<TravelerViewModel> GetTravelerById(int travelerId)
        {
            var traveler = await _travelerRepository.GetTravelerById(travelerId);
            if (traveler == null)
            {
                throw new KeyNotFoundException($"Traveler with Id {travelerId} not found.");
            }

            return _mapper.Map<TravelerViewModel>(traveler);
        }

        // Dodawanie podróżnika
        public async Task AddTraveler(TravelerViewModel travelerViewModel)
        {
            // Validate traveler
            ValidateTraveler(travelerViewModel);

            var traveler = _mapper.Map<Traveler>(travelerViewModel);
            await _travelerRepository.AddTraveler(traveler);
        }

        // Aktualizacja podróżnika
        public async Task UpdateTraveler(TravelerViewModel travelerViewModel)
        {
            // Validate traveler
            ValidateTraveler(travelerViewModel);

            var traveler = _mapper.Map<Traveler>(travelerViewModel);

            // Check if traveler exists
            var existingTraveler = await _travelerRepository.GetTravelerById(traveler.TravelerId);
            if (existingTraveler == null)
            {
                throw new KeyNotFoundException($"Traveler with Id {traveler.TravelerId} not found.");
            }

            await _travelerRepository.UpdateTraveler(traveler);
        }

        // Usuwanie podróżnika
        public async Task DeleteTraveler(int travelerId)
        {
            var traveler = await _travelerRepository.GetTravelerById(travelerId);
            if (traveler == null)
            {
                throw new KeyNotFoundException($"Traveler with Id {travelerId} not found.");
            }

            await _travelerRepository.DeleteTraveler(travelerId);
        }

        // Private method for validating traveler input
        private void ValidateTraveler(TravelerViewModel travelerViewModel)
        {
            var validationContext = new ValidationContext(travelerViewModel);
            var validationResults = new List<ValidationResult>();
            bool isValid = Validator.TryValidateObject(travelerViewModel, validationContext, validationResults, true);

            if (!isValid)
            {
                throw new ArgumentException(string.Join(", ", validationResults.Select(x => x.ErrorMessage)));
            }
        }
    }
}
