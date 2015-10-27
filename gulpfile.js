'use strict';

var gulp = require('gulp');
var ts = require('gulp-typescript');
var jasmine = require('gulp-jasmine');

gulp.task('default',['build']);

gulp.task('build',function(){
	var tsProject = ts.createProject('tsconfig.json');
	var tsResult = gulp.src(['typings/**/*.ts','src/**/*.ts'])
  		.pipe(ts(tsProject));
	return tsResult.js
		.pipe(gulp.dest('dist'));
});

gulp.task('test',['build'],function(){
	return gulp.src('spec/test.js')
	.pipe(jasmine({
		verbose: true
	}));
});