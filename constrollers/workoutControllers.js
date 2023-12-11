const { Mongoose, default: mongoose } = require('mongoose');
const Workout = require('../models/workoutModel')



// get all workouts
const getWorkouts = async(req,res) => {
    const workouts = await Workout.find({}).sort({createdAt : -1});
    
    res.status(200).json(workouts);
}

// get single workout
const getWorkout = async(req,res) => {
    const {id} = req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(404).json({error : 'no such id'})
    }
    const workout = await Workout.findById(id);

    if(!workout)
    {
        return req.status(404).json({error:'no such workout'});
    }

    res.status(200).json(workout);
}


// add a workout 
const createWorkout = async (req, res) => {
    const { title, reps, load } = req.body;

    try {
        const obj = await Workout.create({ title, reps, load });
        res.status(200).json(obj);
    } catch (error) {
        res.status(400).json({ error: 'error message' });
    }
};


//delete a workout

const deleteWorkout = async(req,res) => {
    const {id} = req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        res.status(404).json({error : 'no such id'});
    }

    const workout = await Workout.findOneAndDelete({_id: id});

    if(!workout)
    {
        return res.status(404).json({error : 'no workout with such id'});
    }
    
    res.status(200).json(workout);
}

// updatea workoutc


module.exports = {createWorkout, getWorkouts, getWorkout,deleteWorkout};