const express = require('express');

const {createWorkout , getWorkouts, getWorkout, deleteWorkout} = require('../constrollers/workoutControllers');

const router = express.Router();


// get all workouts
router.get('/',getWorkouts);

//get a single workout
router.get('/:id',getWorkout);

// post a new workout
router.post('/', createWorkout);

// Delete a workout
router.delete('/:id',deleteWorkout);

// update a workout
router.patch('/:id',(req,res)=>{
    res.json({mssg : 'UPDATE a workout'});
});



module.exports = router;
