package com.mizu.pocjwt.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

	Optional<User> findByEmail(String email);
	<T extends User> User save(User user);
	
}
