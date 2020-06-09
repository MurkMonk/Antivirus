#ifndef OBSERVER_H
#define OBSERVER_H
template <typename T>
class Observer {
public:
	virtual void update(T) = 0;
};
#endif
