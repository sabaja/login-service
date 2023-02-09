package com.login.repository.criteria;

import com.login.entity.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class UserCriteriaImpl implements UserCriteria {

    @Autowired
    EntityManager entityManager;

    //    https://spring.io/blog/2011/04/26/advanced-spring-data-jpa-specifications-and-querydsl
    @Override
    public List<User> getLongTermUsers(final User user) {
        LocalDate today = LocalDate.now();

        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = builder.createQuery(User.class);
        Root<User> root = query.from(User.class);

        final LocalDateTime createTime = user.getCreateTime();
        final String createdDate = createTime.toLocalDate().format(DateTimeFormatter.ofPattern("yyyy MM dd"));
        Predicate hasBirthday = builder.equal(root.get(createdDate), today);
        Predicate isLongTermUser = builder.lessThan(root.get(createdDate), today.minusYears(2));
        query.where(builder.and(hasBirthday, isLongTermUser));
        return entityManager.createQuery(query.select(root)).getResultList();
    }
}
