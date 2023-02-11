package com.login.java8.test;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.mockito.internal.util.Supplier;

import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

interface A {
    String getName();

    void setName(String name);

    String getDescription();

    void setDescription(String description);
}

@Slf4j
public class Java8Examples {

    private static final Supplier<String> SUPPLIER = () -> "Ciao";
    private static final Consumer<B> CONSUMER = b -> b.setDescription("QQQQQQQQQQQQ");
    private static final Predicate<B> PREDICATE = b -> "".equals(b.getDescription());
    private static final Function<B, String> FUNCTION = extractBinaryFromStringFunction();

    public static void main(String[] args) {
        Java8Examples m = new Java8Examples();
        List<B> as = List.of(
                new B("Primo", "ciao"),
                new B("Secondo", "ciao"),
                new B("Terzo", "ciao")

        );
        final List<String> descriptions = m.extractElement(as, A::getDescription);
        descriptions.forEach(log::info);


        log.info(SUPPLIER.get());
        as.forEach(CONSUMER);
        as.forEach(e -> log.info("{}", PREDICATE.test(e)));
        as.forEach(e -> log.info(FUNCTION.apply(e)));
    }

    private static Function<B, String> extractBinaryFromStringFunction() {
        return b -> {
            final String description = b.getDescription();
            final char[] chars = description.toCharArray();
            StringBuilder sb = new StringBuilder();
            for (char aChar : chars) {
                sb.append(
                        String.format("%8s", Integer.toBinaryString(aChar)).replace(" ", "0")
                );
            }

            return sb.toString();
        };
    }

    public <T> List<T> extractElement(List<B> as, Function<A, T> aResolver) {
        return as.stream()
                .map(aResolver)
                .toList();
    }

}

@Data
@AllArgsConstructor
class B implements A {

    private String name;
    private String description;

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public void setDescription(String description) {
        this.description = description;
    }
}