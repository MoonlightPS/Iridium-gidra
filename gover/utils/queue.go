package utils

import (
	"errors"
	"sync/atomic"
)

// only for 1 read and 1 write model
type Queue[T any] struct {
	c    chan T
	cap  int
	flag int32
}

func (q *Queue[T]) Enqueue(data T) error {
	if len(q.c) >= q.cap {
		return errors.New("queue is full")
	}
	if atomic.LoadInt32(&q.flag) != 0 {
		return errors.New("queue is close")
	}
	q.c <- data
	return nil
}

func (q *Queue[T]) Dequeue() T {
	return <-q.c
}

func (q *Queue[T]) Close() {
	atomic.AddInt32(&q.flag, 1)
	close(q.c)
}

func NewQueue[T any](size int) *Queue[T] {
	return &Queue[T]{
		c:   make(chan T, size),
		cap: size,
	}
}
