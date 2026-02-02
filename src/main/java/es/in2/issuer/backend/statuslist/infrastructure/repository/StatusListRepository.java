package es.in2.issuer.backend.statuslist.infrastructure.repository;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Spring Data R2DBC repository for table: status_list
 */
public interface StatusListRepository extends ReactiveCrudRepository<StatusList, Long> {

    @Query("""
           SELECT *
           FROM status_list
           WHERE purpose = :purpose
           ORDER BY id DESC
           LIMIT 1
           """)
    Mono<StatusList> findLatestByPurpose(String purpose);

    @Query("""
       UPDATE status_list
       SET encoded_list = :encodedList,
           signed_credential = :signedCredential,
           updated_at = NOW()
       WHERE id = :id
         AND updated_at = :expectedUpdatedAt
       """)
    Mono<Integer> updateSignedAndEncodedIfUnchanged(
            Long id,
            String encodedList,
            String signedCredential,
            Instant expectedUpdatedAt
    );

    @Modifying
    @Query("""
       UPDATE status_list
       SET signed_credential = :signedCredential,
           updated_at = NOW()
       WHERE id = :id
       """)
    Mono<Integer> updateSignedCredential(Long id, String signedCredential);

}


