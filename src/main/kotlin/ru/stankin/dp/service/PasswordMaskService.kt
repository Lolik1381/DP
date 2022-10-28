package ru.stankin.dp.service

import org.springframework.stereotype.Service
import ru.stankin.dp.dto.PasswordMask

@Service
class PasswordMaskService {

    companion object {
        var masks = listOf(
            PasswordMask(
                id = "13",
                description = "Наличие строчных и прописных букв, а также знаков препинания",
                regex = listOf("[a-z]+", "[A-Z]+", "[,\\[\\]:!\\-\\(\\)\\.?;']+")
            ),
            PasswordMask(
                id = "1",
                description = "Без ограничений",
                regex = listOf()
            )
        )
    }

    fun getAllPasswordMask(): List<PasswordMask> {
        return masks
    }

    fun findMaskById(id: String): PasswordMask {
        return masks.find { it.id == id }!!
    }
}